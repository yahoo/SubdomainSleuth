/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"net"

	"github.com/miekg/dns"
)

// Send a recursive query to one of the configured resolvers.  Rotate through
// all of them to spread out the load.
func RecursiveQuery(name string, t uint16) (r *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetQuestion(name, t)
	m.RecursionDesired = true
	resolver_idx++
	resolver := resolvers[resolver_idx%len(resolvers)]

	r, _, err = client.Exchange(m, net.JoinHostPort(resolver, "53"))

	// If the UDP query came back truncated, retry with TCP.
	if r.Truncated {
		logger.Debugw("UDP response truncated, retrying with TCP", "name", name, "type", t, "resolver", resolver)
		// Increase the buffer size to 4096 bytes.
		m.SetEdns0(4096, true)
		r, _, err = tcpclient.Exchange(m, net.JoinHostPort(resolver, "53"))
	}

	// fmt.Printf("Query: %v\n", m)
	// fmt.Printf("CNAME error: %v\n", err)
	// fmt.Printf("Response: %v\n", r)

	return
}

// Send an authoritative query directly to a particular server.
func DirectQuery(name string, t uint16, server net.IP) (r *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetQuestion(name, t)
	m.RecursionDesired = false
	r, _, err = client.Exchange(m, net.JoinHostPort(server.String(), "53"))

	return
}

// Send a recursive query directly to a particular server.
func DirectRecursiveQuery(name string, t uint16, server net.IP) (r *dns.Msg, err error) {
	m := new(dns.Msg)
	m.SetQuestion(name, t)
	m.RecursionDesired = true
	r, _, err = client.Exchange(m, net.JoinHostPort(server.String(), "53"))

	return
}
