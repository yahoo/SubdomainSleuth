/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"github.com/miekg/dns"
)

// Checker is the interface used by check plugins.
type Checker interface {
	Init() error
	Check(dns.RR) error
}
