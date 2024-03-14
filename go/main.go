/*
Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See
LICENSE file in project root for terms.
*/

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var client dns.Client

var results Results = make([]Result, 0)

type resolverFlag []string

func (s *resolverFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *resolverFlag) String() string {
	return fmt.Sprint(*s)
}

type checkFlag []string

func (s *checkFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *checkFlag) String() string {
	return fmt.Sprint(*s)
}

var resolvers resolverFlag // This is typed, but it's still also a []string and can be used that way.
var checks checkFlag
var resolver_idx int
var read_stdin bool
var logLevel *zapcore.Level
var output_filename string

// var httpcheck HttpChecker

var logger *zap.SugaredLogger
var connectivity Connectivity

func main() {
	flag.Var(&resolvers, "resolver", "resolver to use for DNS resolution, may specify more than once.  <IP>:53")
	flag.Var(&checks, "check", "Check to execute, may specify more than once.")
	flag.BoolVar(&read_stdin, "stdin", false, "Indicates to read zone files from stdin")
	flag.StringVar(&output_filename, "output", "-", "Output file name, or '-' for stdout")
	logLevel = zap.LevelFlag("logging", zap.WarnLevel, "Log level (error, warn, info, debug)")

	flag.Parse()

	// Start with a generic config and then set the level.
	logConfig := zap.NewDevelopmentConfig()
	logConfig.Level = zap.NewAtomicLevelAt(*logLevel)

	plogger, _ := logConfig.Build()
	logger = plogger.Sugar()

	if len(resolvers) == 0 {
		resolvers = parseResolvConf()
	}
	// If we didn't get any resolvers, bail out immediately.
	if len(resolvers) == 0 {
		logger.Fatalf("No resolvers specified - exiting.\n")
		os.Exit(1)
	}

	logger.Infow("In main")
	logger.Infof("Resolvers: %v\n", resolvers)
	logger.Infof("Files: %v\n", flag.Args())
	logger.Infof("Checks: %v\n", checks)

	var err error
	var output_file *os.File

	// Open our output file here.  We don't want to spend the time running the
	// scan only for the output file open to fail.  If our filename is "-", use
	// standard output.  This is the default.  Otherwise, we've gotten a file
	// name to use.
	if output_filename == "-" {
		output_file = os.Stdout
	} else {
		output_file, err = os.Create(output_filename)
		if err != nil {
			logger.Fatalf("Unable to open output file %s", output_filename)
			os.Exit(1)
		}
		defer output_file.Close()
	}

	// Check our connectivity.  Certain checks require direct IPv4 and IPv6
	// connectivity to remote authoritative servers.
	connectivity = CheckConnectivity()

	// Initialize the checks we're using
	for _, check := range checks {
		checkerRegistry[check].Init()
	}

	// Disable HTTPS cert verification for our HTTP checks.  We don't want cert
	// issues to prvent us from spotting potential takeovers.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if read_stdin {
		// If we're using stdin, read zone file paths from stdin and check them.
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fn := scanner.Text()
			logger.Infof("Scanning file %s\n", fn)
			checkZoneFile(fn)
		}
		if err := scanner.Err(); err != nil {
			log.Println(err)
		}
	} else {
		// If we're using arguments for zone files, but didn't get any, bail
		// out.
		if len(flag.Args()) == 0 {
			logger.Fatalf("No zones specified - exiting\n")
			os.Exit(1)
		}

		// If we did get zone file arguments, check them.
		for _, f := range flag.Args() {
			checkZoneFile(f)
		}
	}

	// Write our output as JSON to the output_file.  This may be a normal file
	// or it could be stdout.
	out, _ := json.MarshalIndent(results, "", "  ")
	output_file.Write(out)
	output_file.Sync()
}

// Parse a zone file and run all the records found through the check plugins.
func checkZoneFile(fn string) {
	// We treat the file name as the zone name.  Records that aren't fully
	// qualified are interpreted relative to this.
	zn := path.Base(fn)

	rzonefile, err := os.Open(fn)
	if err != nil {
		logger.Errorf("Error opening file %s: %s\n", fn, err)
	}
	defer rzonefile.Close()

	zonefile := bufio.NewReader(rzonefile)

	logger.Infow("Reading zone file", "file", fn, "zone", zn)

	zp := dns.NewZoneParser(zonefile, zn, fn)

	// Iterate over all of the records we find, and run them through the various checks.
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		checkRecord(rr)
	}
}

// Run a particular record through each check.
func checkRecord(rr dns.RR) {
	for _, check := range checks {
		checkerRegistry[check].Check(rr)
	}
}

// Extract resolvers from /etc/resolv.conf, if any.
func parseResolvConf() (resolvers []string) {
	fn := "/etc/resolv.conf"

	logger.Infof("Trying to determine resolvers from '%s'.\n", fn)
	clientConfig, err := dns.ClientConfigFromFile(fn)
	if errors.Is(err, os.ErrNotExist) {
		logger.Infof("No such file.\n")
		return
	}
	if err != nil {
		logger.Errorf("Error parsing file '%s': %s\n", fn, err)
		return
	}
	resolvers = clientConfig.Servers
	return
}
