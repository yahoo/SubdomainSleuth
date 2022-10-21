/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"net"

	"github.com/miekg/dns"
)

type Connectivity struct {
	Resolvers bool
	Ipv4      bool
	Ipv6      bool
}

// Test our IPv4 and IPv6 connectivity by sending queries directly to public
// resolvers. Some checks directly talk to remote name servers, so we need to
// know if we have connectivity if we're going to trust our results.
func CheckConnectivity() (results Connectivity) {
	/*
		We'll test things by sending queries directly to these public
		resolvers.  We test IPv4 and IPv6 seperately.

		* Cloudflare
			* 1.1.1.1
			* 1.0.0.1
			* 2606:4700:4700::1111
			* 2606:4700:4700::1001
		* Google
			* 8.8.8.8
			* 8.8.4.4
			* 2001:4860:4860::8888
			* 2001:4860:4860::8844
		* Quad9
			* 9.9.9.9
			* 149.112.112.112
			* 2620:fe::fe
			* 2620:fe::9
	*/

	// IPs above broken down into arrays by protocol.
	ipv4Tests := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
	ipv6Tests := []string{"2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9"}

	ipv4Success := 0
	for _, t := range ipv4Tests {
		logger.Debugw("Testing IPv4 connectivity", "target", t)
		reply, err := DirectRecursiveQuery("yahoo.com.", dns.TypeSOA, net.ParseIP(t))

		if err != nil {
			logger.Debugw("Error", "err", err)
			continue
		}

		if reply == nil {
			continue
		}

		found := false

		for _, answer := range reply.Answer {
			if answer.Header().Rrtype == dns.TypeSOA {
				found = true
			}
		}

		if found {
			ipv4Success++
		}

		logger.Debugw("Tested IPv4 connecvity", "target", t, "result", found)

	}

	if ipv4Success == len(ipv4Tests) {
		results.Ipv4 = true
	}

	ipv6Success := 0
	for _, t := range ipv6Tests {
		logger.Debugw("Testing IPv6 connectivity", "target", t)
		reply, err := DirectRecursiveQuery("yahoo.com.", dns.TypeSOA, net.ParseIP(t))

		if err != nil || reply == nil {
			continue
		}

		found := false

		for _, answer := range reply.Answer {
			if answer.Header().Rrtype == dns.TypeSOA {
				found = true
			}
		}

		if found {
			ipv6Success++
		}

		logger.Debugw("Tested IPv6 connecvity", "target", t, "result", found)
	}

	if ipv6Success == len(ipv6Tests) {
		results.Ipv6 = true
	}

	resolverSuccess := 0
	for _, t := range resolvers {
		logger.Debugw("Testing resolver", "target", t)
		reply, err := DirectRecursiveQuery("yahoo.com.", dns.TypeSOA, net.ParseIP(t))

		if err != nil || reply == nil {
			continue
		}

		found := false

		for _, answer := range reply.Answer {
			if answer.Header().Rrtype == dns.TypeSOA {
				found = true
			}
		}

		if found {
			resolverSuccess++
		}

		logger.Debugw("Tested resolver", "target", t, "result", found)
	}

	if resolverSuccess == len(resolvers) {
		results.Resolvers = true
	}

	logger.Infof("Connectivity results: %v", results)
	return
}
