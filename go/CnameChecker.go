/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// This check is designed to identify dangling CNAMEs.  A dangling CNAME is
// defined as a CNAME that points to something that doesn't exist.  Since
// CNAMEs may be chained, this break may occur at any point in that chain.
//
// To check, we perform several recursive lookups on the target of the CNAME.
// We currently check for A, AAAA, and TXT records.  If any of these types
// exist in the answer, we consider the CNAME to be valid.  If not, it is
// considered to be dangling.
//
// We could use a single ANY query instead of separate queries for A, AAA, and
// TXT, but I've found that this isn't reliable in the wild.  Different servers
// may not give complete answers for an ANY query.  As such, we do separate
// lookups.

// These are the type of targets that we try to resolve for CNAMEs to see if
// they're valid.  If we don't find one of these, we consider the CNAME to be
// dangling.
var cnameTargetTypes []uint16 = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}

// Register ourselves as an available plugin.
func init() {
	RegisterChecker("cname", &CnameChecker{})
}

// This is the object itself.  This check has no internal state, so its just
// an empty struct.
type CnameChecker struct {
}

// Nothing to initialize, but this is required to meet the interface.
func (self *CnameChecker) Init() (err error) {
	logger.Warnf("Initializing check plugin", "check", "cname2")
	return
}

// This is the actual check logic.
func (self *CnameChecker) Check(record dns.RR) (err error) {
	// Check the type of the RR.  If it's a CNAME, capture the record as the
	// proper type.  If not, just return.
	cname, ok := record.(*dns.CNAME)
	if !ok {
		return
	}

	logger.Infow("Checking record", "record", cname.Header().Name, "check", "cname")

	// This is the total number of answers we've found.  We require there to
	// be at least one for the record to be valid, but there could be more.
	answers := 0

	// Perform a lookup for each of the target types.
	for _, t := range cnameTargetTypes {
		logger.Debugw("Resolving CNAME target", "record", cname.Header().Name, "target", cname.Target, "type", dns.Type(t))
		msg, err := RecursiveQuery(cname.Target, t)

		// If we get an error on one of the lookups, just keep going.  Broken
		// records can fail in strange ways.  Maybe SERVFAIL or NXDOMAIN, or
		// other errors.  If we got an empty response, do the same.
		if err != nil || msg == nil {
			logger.Debugw("Error resolving CNAME target", "record", cname.Header().Name, "target", cname.Target, "type", dns.Type(t), "err", err)
			continue
		}

		// For each answer, see if we actually got an answer of that type.  It
		// is possible that we could have CNAMEs to CNAMEs to CNAMEs, so check
		// all of the answers we received.  If we sent a query for an A record,
		// we need to get back an A record for it to be valid.
		for _, answer := range msg.Answer {
			if answer.Header().Rrtype == t {
				answers++
			}
		}
	}

	logger.Debugf("Found %d answers for %s", answers, cname.Header().Name)

	// If answers is zero, that means we didn't find any of the record types
	// that we were looking for.  That means we consider this record dangling,
	// or at least highly suspicious.
	if answers == 0 {
		logger.Infow("Found no answers for CNAME", "record", cname.Header().Name, "target", cname.Target)
		results.Add(Result{cname.Header().Name, time.Now(), "cname", cname.Target, fmt.Sprintf("Dangling CNAME %s -> %s", cname.Header().Name, cname.Target)})
	}

	return
}
