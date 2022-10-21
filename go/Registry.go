/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

var checkerRegistry map[string]Checker

// RegisterChecker registers a Checker.  Surprise!
func RegisterChecker(name string, checker Checker) {
	if checkerRegistry == nil {
		checkerRegistry = make(map[string]Checker)
	}

	checkerRegistry[name] = checker
}
