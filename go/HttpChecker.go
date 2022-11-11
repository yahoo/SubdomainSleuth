/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/yl2chen/cidranger"

	_ "embed"
)

//go:embed fingerprints.json
var DEFAULT_FINGERPRINTS []byte

func init() {
	RegisterChecker("http-fingerprint", &HttpChecker{})
}

func (self *HttpChecker) Init() (err error) {
	logger.Infow("Initializing check plugin", "check", "http-fingerprint")
	self.LoadFingerprints()
	return
}

type HttpFingerprint struct {
	Service     string           `json:"service"`
	Cname       []string         `json:"cname"`
	Addresses   []string         `json:"address"`
	Ranger      cidranger.Ranger `json:"-"`
	Fingerprint []string         `json:"fingerprint"`
	Nxdomain    []string         `json:"nxdomain"`
	UrlTemplate string           `json:"template"`
}

// We loaded the raw list of addresses from the fingerprint definition file,
// but we need to convert that into a cidranger.Ranger for faster lookups.  We
// also set a default URL template if one wasn't provided.
func (self *HttpFingerprint) Load() (err error) {
	self.Ranger = cidranger.NewPCTrieRanger()

	for _, addr := range self.Addresses {
		_, ipnet, _ := net.ParseCIDR(addr)
		if err != nil {
			logger.Warnf("Error parsing fingerprint IP %s", addr)
			continue
		}
		self.Ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))
	}

	// If we didn't get a UrlTemplate from the JSON, set a default here.
	if self.UrlTemplate == "" {
		self.UrlTemplate = "http://%s"
	}

	return
}

// Check if this fingerprint matches this record.  This could be for a CNAME
// or A/AAAA record match.  Then we build a URL based on a template, and do
// an HTTP get.  We compare the response we get back to the list of fingerprint
// strings.  If there is a match, we consider this a bad record.  We do the
// recursive lookup in the  calling function so that we can do that only once
// and use it for every fingerprint.
func (self *HttpFingerprint) Check(rr dns.RR, answers []dns.RR) {
	// Keep track if one or more criteria for this fingerprint matched.  If any
	// of the criteria match, we need to send an HTTP request to test it.
	match := false

	// Loop through all the answers we got back, and see if any of them match
	// this fingerprint.  If this was an A/AAAA record, the answers array will
	// contain the same record as rr.  For example, the fingerprint might match a CNAME.
	// It may also match at any level.  For example, we might have a CNAME to a
	// CNAME to an unclaimed S3 bucket.  We need to check each answer.
	for _, answer := range answers {
		switch arr := answer.(type) {

		case *dns.CNAME:
			// For each CNAME match in this fingerprint, see if the CNAME in
			// the answer contains it.  This is a subdomain match.  Eg,
			// foo.s3.amazonaws.com should match a fingerprint of .s3.amazonaws.
			for _, cn := range self.Cname {
				if strings.Contains(arr.Target, cn) {
					logger.Infof("Matched %s on CNAME %s -> %s (%s)\n", rr.Header().Name, arr.Header().Name, arr.Target, arr)
					match = true
				}
			}
		case *dns.A:
			contains, _ := self.Ranger.Contains(arr.A)
			if contains {
				logger.Infof("Matched %s on A to %s (%s)\n", rr.Header().Name, self.Service, arr)
				match = true
			}
		case *dns.AAAA:
			contains, _ := self.Ranger.Contains(arr.AAAA)
			if contains {
				logger.Infof("Matched %s on AAAA to %s (%s)\n", rr.Header().Name, self.Service, arr)
				match = true
			}
		}

		// If we match any criteria, we don't need to keep checking.
		if match {
			break
		}
	}

	if !match {
		return
	}

	logger.Debugf("Record %s matched fingerprint criteria for %s", rr.Header().Name, self.Service)

	// Remove the trailing dot from the hostname, and use the UrlTemplate to
	// convert the hostname into a URL to test.
	name := strings.TrimSuffix(rr.Header().Name, ".")
	url := fmt.Sprintf(self.UrlTemplate, name)

	logger.Debugf("Using URL %s\n", url)

	// Fetch the URL contents
	content, _ := GetHttp(url)

	// Check each of our fingerprint strings to see if it exists in the content
	// we got from the server.
	for _, fingerprint := range self.Fingerprint {
		if strings.Contains(string(content), fingerprint) {
			results.Add(Result{rr.Header().Name, time.Now(), "http", fingerprint, fmt.Sprintf("Dangling site %s -> %s (%s)", rr.Header().Name, self.Service, fingerprint)})
		}
	}

}

type HttpChecker struct {
	fingerprints []HttpFingerprint
}

func (self *HttpChecker) Check(record dns.RR) (err error) {
	var answers []dns.RR
	resolved := false

	logger.Infow("Checking record", "record", record.Header().Name, "check", "http-fingerprint")

	// If this is a CNAME, do a recursive lookup on it.  If it's an A/AAAA
	// record, we have the information locally.  We need to do a recursive
	// lookup, because there might be intermediate CNAMEs between our record
	// and the one that matches the signature.
	if record.Header().Rrtype == dns.TypeCNAME {

		msg, err2 := RecursiveQuery(record.Header().Name, dns.TypeA)

		if err2 != nil {
			logger.Debugf("Error doing recursive lookup", "record", record.Header().Name, "error", err)
			return err2
		}

		// Check if we found an A/AAAA for the CNAME.  If not, ignore silently.
		// Let the CNAME check handle these.
		for _, answer := range msg.Answer {
			if answer.Header().Rrtype == dns.TypeA || answer.Header().Rrtype == dns.TypeAAAA {
				resolved = true
			}
		}

		answers = msg.Answer
	} else {
		resolved = true
		answers = []dns.RR{record}
	}

	// If we couldn't resolve this to an A or AAAA, silently ignore because
	// there isn't anything to test.  This is a dangling CNAME.
	if !resolved {
		return
	}

	// For each of the fingerprints we have, compare this record against each of them.
	for _, fingerprint := range self.fingerprints {
		fingerprint.Check(record, answers)
	}

	return
}

// Load the fingerprint definitions.  We're using go:embed to embed the
// fingerprint data into the executable.  This avoids having to having to
// distribute the fingerprints.json file with the executable or configuring
// where to find it.
func (self *HttpChecker) LoadFingerprints() (err error) {
	err = json.Unmarshal(DEFAULT_FINGERPRINTS, &self.fingerprints)

	// Use array access so that we update the original rather than a copy.
	for i := range self.fingerprints {
		self.fingerprints[i].Load()
	}
	return
}

// GetHttp performs an HTTP/HTTPS request to a URL and returns the content and
// any error.
func GetHttp(url string) (content []byte, err error) {
	resp, err := http.Get(url)
	if err != nil {
		logger.Infof("HTTP GET error on %s: %s\n", url, err)
		return
	}

	defer resp.Body.Close()

	content, err = io.ReadAll(resp.Body)
	if err != nil {
		logger.Infof("HTTP GET body error on %s: %s", url, err)
		return
	}

	return
}
