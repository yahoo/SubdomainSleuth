/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"time"
)

// The Result type represents a dangling record and the metadata about it.
type Result struct {
	Name        string    `json:"name"`
	Date        time.Time `json:"detected"`
	Check       string    `json:"check"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
}

type Results []Result

func (results *Results) Add(result Result) {
	logger.Infof("Added result - %s %s\n", result.Name, result.Description)
	*results = append(*results, result)
}
