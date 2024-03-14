#!/usr/bin/python

import json
import sys
import argparse

results = {}

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', type=argparse.FileType('r'), action="append")
parser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout)

options = parser.parse_args()

for input in options.input:
    data = json.load(input)

    for item in data:
        key = "%s-%s-%s" % (item["name"], item["check"], item["target"])
        results[key] = item

output = []
for value in results.values():
    output.append(value)


json.dump(output, options.output, indent=2, sort_keys=True)
options.output.write("\n")
options.output.flush()
sys.stderr.write("Wrote %d records\n" % (len(results)))
