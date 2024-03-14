

# Subdomain Sleuth
> Scanner to identify dangling DNS records and subdomain takeovers.

## Table of Contents
- [Subdomain Sleuth](#subdomain-sleuth)
  - [Table of Contents](#table-of-contents)
  - [Background](#background)
  - [Install](#install)
  - [Usage](#usage)
  - [Security](#security)
  - [Contribute](#contribute)
  - [License](#license)
  - [Checks](#checks)
    - [CNAME](#cname)
    - [NS](#ns)
    - [HTTP Fingerprint](#http-fingerprint)
  - [Internals](#internals)
    - [Performing Lookups](#performing-lookups)
    - [Connectivity](#connectivity)
    - [Logging](#logging)
    - [IP address comparisons](#ip-address-comparisons)
    - [Fingerprints](#fingerprints)
  - [Utilities](#utilities)
  - [Other Tools](#other-tools)


## Background
This tool is designed to help secure your DNS infrastructure by scanning for bad records that might be used for a subdomain takeover.  It reads DNS zone files in Bind/RFC 1035 format, performs a series of validation checks to identify broken records, and generates a report.

A subdomain takeover is when an attacker is able to take control of the target of an existing DNS record.  This is normally the result of what we call a “dangling record”, which is a record that points to something that either doesn’t exist or does exist but isn’t under your control.  That could be a broken CNAME, it could be a bad NS record, or it could be a reference to a service that resolves but that you don’t manage.  If an attacker successfully takes over a name, they can serve any content they want under your domain.  That could be used for phishing or other types of attacks.

## Install
* Change to the "go" directory
* Run `go build`
    * This will download the necessary libraries and build against them.
* Copy the `SubdomainSleuth` executable to a convenient location

## Usage
This tool sometimes needs to make DNS queries directly to remote servers.  As such, you need to run it on a host that has direct Internet access to external DNS servers.  If your firewall filters outbound DNS queries, you may see failures.  Likewise, to check IPv6 resources you'll need to have IPv6 connectivity.

First, you need to specify recursive resolvers that you can use to execute queries.  You specify these on the command line using the `--resolver` flag, which you may specify multiple times.  If no resolver is specified, then the tool will attempt to extract resolvers from `/etc/resolv.conf` if that file exists.  `SubdomainSleuth` will cycle through all given resolvers to even out the load.  This tool may execute _MANY_ queries, so use resolvers that have plenty of capacity.

Next, you need to choose which checks to execute.  These include the `cname`, `ns`, and `http-fingerprint` checks.  You specify these with the `--check` flag and the name of the check to execute.  You can specify multiple checks, and it will execute all of them.

Finally, you need to provide a set of zone files to check.  If the number is small, you can provide one or more on the command line.  If you have a large number of zones, you can add `--stdin` on the command line, and pipe in a list of files to check.

When the run is finished, it will output JSON data with information about each bad record.  You can then use this data to clean up records, generate reports, or any other purpose.

To use localhost as a resolver and execute the `cname` and `ns` checks on the zone file `example.com`, your command would look like this:

```
SubdomainSleuth --resolver=127.0.0.1 --check=cname --check=ns /etc/named/zones/example.com
```

To use a list of zone files on standard input, the same checks would look like this:
```
find /etc/named/zones -type f | SubdomainSleuth --resolver=127.0.0.1 --check=cname --check=ns --stdin
```

## Security
This tool doesn't provide any services or listen on the network, but it does talk to external network resources.  As such, you should never run it under a privileged account where it might cause any damage if it were tricked into executing any code.

You should also update periodically to get new fixes and security signatures.

## Contribute
Our goal for this tool is to help people defend the DNS infrastructure.  Attackers have many tools at their disposal, but defenders seem to have relatively few.  If you find issues that this tool doesn't detect, please help us to improve it.  Attackers are always finding new resources and techniques, so please feed your fixes back into the project to help everyone.

## License
This project is licensed under the terms of the [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0.html) open source license.
Please refer to [LICENSE](LICENSE.txt) for the full terms.

## Checks
This tool provides several different checks that you can use.  You can perform one or multiple checks per run.

### CNAME
This check is designed to identify dangling CNAMEs.  A dangling CNAME is defined as a CNAME that points to something that doesn't exist.  Since CNAMEs may be chained, this break may occur at any point in that chain.

To check, we perform several recursive lookups on the target of the CNAME.  We currently check for A, AAAA, and TXT records.  If any of these types exist in the answer, we consider the CNAME to be valid.  If not, it is considered to be dangling.

### NS
This check is designed to identify lame delegations and other problems with NS records.  This includes NS records that cannot be resolved, name servers that aren't reachable, and name servers that won't answer for the zone that is delegated to them.

We check by resolving the target name server, and then sending an SOA query for the zone being elegated directly to the server.  This is done for both IPv4 and IPv6 if they're available.  Failure to resolve the target name server is an error.  It is also an error if our SOA query doesn't result in an SOA for the name being delegated.

### HTTP Fingerprint
The HTTP fingerprint check uses a fingerprint file with multiple rules.  If a record matches one of these rules, we perform an HTTP request.  We then compare the reponse against the signatures defined in the fingerprint file.  If one of them matches, the resource is considered bad.

One of the most common examples of this is for Amazon AWS S3 buckets.  If a CNAME points to a target containing `s3.amazonaws`, we'll do an HTTP request for the name.  If the bucket isn't claimed, the response will include the string `The specified bucket`.  If it does, we consider this to be a dangling record to an unclaimed S3 bucket.

## Internals
### Performing Lookups
This project uses the DNS library from https://github.com/miekg/dns to perform all lookups.  It has the flexibility to directly query servers using any query type, as well as getting access to the raw DNS messages.  The lookups that this does wouldn't be possible with gethostbyname or the equivalent.

When performing lookups that are likely to fail, checking for errors and rcodes can be unhelpful.  For example, a query might return back that the query was successful but with no answers that we want.  Instead of checking for errors or response codes, the code in this tool mostly checks to see if it found an answer of the type it was expecting.  For example, if you perform a lookup for a label of a particular type, and the label exists but the type doesn't, you'll get NOERROR but also no results.  In short, just because a query comes back successfully doesn't mean that the data you're looking for exists.  Verify that the answer you're expecting is actually there.

### Connectivity
Some checks, like the CNAME checks, only require access to a functional recursive resolver.  Other checks, such as the NS checks, require direct connectivity to remote servers.  These checks may need need to be done over IPv4 or IPv6 specifically.  We try to test connectivity at startup by sending queries to several open resolvers over IPv4 and IPv6.  After that, we log warnings for checks that we're unable to complete due to connectivity limits.

### Logging
This project uses the Zap library (https://github.com/uber-go/zap) for logging.  By default, the tool should run with WARN level logging.

* ERROR - any issue that would impact an entire run or an entire zone should log at this level.
* WARN - Information about the final results for a record.  Successful checks should never issue a WARN.
* INFO - Status info about checks on a zone or record.  This may include both successful and unsuccessful results.
* DEBUG - Anything goes.  May include multiple messages per record.

### IP address comparisons
To compare an A or AAAA against a list of multiple subnets, we use the cidranger library (https://github.com/yl2chen/cidranger).  It uses a tree structure to do efficient longest-match comparisons against large numbers of subnets.

### Fingerprints
The fingerprints file for this project was originally based on https://github.com/haccer/subjack.  It's been expaneded to allow the fingerprint file to contain well-known IPs and subnets for cases where CNAMEs aren't used.  Several additional signatures have also been added.  Adding new fingerprints, and reviewing and refreshing old ones, is a great way to contribute to the project.  The original file was also released under the Apache 2.0 License.

## Utilities
There are also several simple utility scripts in the `scripts` directory.  They all use the same JSON format as the scanner outputs.

* `grep.py` - Searches input on one or more fields to narrow down the results.
* `labels.py` - Summarizes the number of results at different labels.  Eg, `foo1.elb.amazonaws.com` summarized at `-l3` becomes `elb.amazonaws.com`.  Useful to identify similar problems for remediation.
* `csvout.py` - Outputs CSV for generating spreadsheets or reports.

They're also inteded to work together.  For example, you can do things like:

`cat output.json | python scripts/grep.py -t amazonaws.com | python3 scripts/labels.py -l3`

This will filter the results to only ones with a target containing amazonaws.com and then sumamrize at the 3rd label.

`cat output.json | python scripts/grep.py -c cname -t dkim.amazonses.com | python3 scripts/csvout.py -f name -f check -f target`  

This will filter the results to only broken CNAMEs to AWS DKIM records and then output a CSV with the name, the check, and the target.

## Other Tools
* cli53 - Users have reported that they have successfully exported zones from AWS using cli53 and were able to scan them with Subdomain Sleuth.  See https://github.com/barnybug/cli53 and https://github.com/yahoo/SubdomainSleuth/issues/3.
