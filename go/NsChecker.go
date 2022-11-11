/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// This check is designed to identify lame delegations and other problems with
// NS records.  This includes NS records that cannot be resolved, name servers
// that aren't reachable, and name servers that won't answer for the zone that
// is delegated to them.

// We check by resolving the target name server, and then sending an SOA
// query for the zone being delegated directly to the server.  This is done
// for both IPv4 and IPv6 if they're available.  Failure to resolve the target
// name server is an error.  It is also an error if our SOA query doesn't
// result in an SOA for the name being delegated.

// Register ourselves as an available plugin.
func init() {
	RegisterChecker("ns", &NsChecker{})
}

// This is the object itself.  This check has no internal state, so its just
// an empty struct.
type NsChecker struct {
}

// Nothing to initialize, but this is required to meet the interface.
func (self *NsChecker) Init() (err error) {
	logger.Infow("Initializing check plugin", "check", "ns")
	return
}

// Each NS record will refer to a single NS
func (self *NsChecker) Check(record dns.RR) (err error) {
	// Check the type of the RR.  If it's an NS, capture the record as the
	// propper type.  If not, just return.
	ns, ok := record.(*dns.NS)
	if !ok {
		return
	}

	logger.Infow("Checking record", "record", ns.Header().Name, "check", "ns")

	// This is the total number of answers found for A and AAAA lookups for
	// this name server.
	answers := 0

	// Try to resolve the name server name.  Check both A and AAAA.  If either
	// one exists, succeed.
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		logger.Infow("Resolving NS nameserver", "record", ns.Header().Header(), "ns", ns.Ns, "type", dns.Type(t))
		r, err := RecursiveQuery(ns.Ns, t)

		// If we get an error on one of the lookups, just keep going.  Broken
		// records can fail in strange ways.  Maybe SERVFAIL or NXDOMAIN, or
		// other errors.  If we got an empty response, do the same.
		if err != nil || r == nil {
			logger.Debugw("Error resolving NS nameserver target", "record", ns.Header().Name, "nameserver", ns.Ns, "type", dns.Type(t), "err", err)
			continue
		}

		// Go through each answer.  Count up all the answers as we go.  For
		// every answer, send a test query to each one to see if it answerss.
		for _, answer := range r.Answer {
			switch a := answer.(type) {
			case *dns.A:
				if connectivity.Ipv4 {
					answers++
					self.checkSOA(ns, a.A)
				} else {
					logger.Infow("Unable to check record because no IPv4 connectivity", "record", ns.Header().Name, "target", ns.Ns)
				}
			case *dns.AAAA:
				if connectivity.Ipv6 {
					answers++
					self.checkSOA(ns, a.AAAA)
				} else {
					logger.Infow("Unable to check record because no IPv6 connectivity", "record", ns.Header().Name, "target", ns.Ns)
				}

			default:
			}
		}
	}

	logger.Debugw("Resolved NS record", "record", ns.Header().Name, "nameserver", ns.Ns, "results", answers)

	// Since an NS record refers to a single name server, and we're checking
	// for both A and AAAA records for it, we should have either 1 or 2
	// answers here.  If we have zero, it's because all of our lookups for
	// this server failed.
	if answers == 0 {

		results.Add(Result{ns.Hdr.Name, time.Now(), "ns", ns.Ns, fmt.Sprintf("Dangling NS %s -> %s: Target NS name doesn't exist", ns.Header().Name, ns.Ns)})
	}

	return
}

// Send an SOA query directly to the name server for the zone delegated to it.
// An SOA query should always succeed if the server is willing to answer for
// that zone.
func (self *NsChecker) checkSOA(ns *dns.NS, server net.IP) (err error) {
	name := dns.Fqdn(ns.Header().Name)

	// Send this directly to the server, not through normal recursion
	reply, err := DirectQuery(name, dns.TypeSOA, server)
	found := false

	// Catch if the server is unreachable or gives an error of some kind so that we can provide more detail.
	if err != nil || reply == nil {
		results.Add(Result{ns.Header().Name, time.Now(), "ns", ns.Ns, fmt.Sprintf("Dangling NS %s -> %s: Target NS query failed", ns.Header().Name, ns.Ns)})
		return
	}

	// If we got an answer back, see if we have an SOA record for the zone
	// that was delegated.  If we get an SOA but it isn't an exact match,
	// something funny is going on and should be checked.
	for _, answer := range reply.Answer {
		if answer.Header().Rrtype == dns.TypeSOA && answer.Header().Name == name {
			found = true
		}
	}

	// If we didn't get the right SOA, report it.
	if !found {
		results.Add(Result{ns.Header().Name, time.Now(), "ns", ns.Ns, fmt.Sprintf("Dangling NS %s -> %s: Target NS doesn't answer for this name", ns.Header().Name, ns.Ns)})
	}

	return
}
