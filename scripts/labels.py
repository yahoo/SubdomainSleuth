import argparse
import json
import sys

# This script is used to summarize the number of outputs at different number of
# record labels.  This is useful to identify the different types of broken
# records that you have for triage or statistical purposes.
# 
# For example, you have broken CNAMES foo1.elb.amazonaws.com,
# bar2.elb.amazonaws.com, and baz3.s3.amazonaws.com. If you summarize at two
# labels, you'd see 3 results at amazonaws.com.  If you summarize at three
# labels, you'd see 1 for s3.amazonaws.com and 2 for elb.amazonaws.com.

# Usage:
# cat output.json | python3 scripts/labels.py -l3


input = []

counts = {}

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', type=argparse.FileType('r'), default=sys.stdin)
parser.add_argument('-l', '--labels', type=int, default=1)
parser.add_argument('-f', '--field', default='target')

options = parser.parse_args()

input = json.load(options.input)

lcount = options.labels * -1

for result in input:
    if result['check'] != 'cname':
        continue
    
    labels = result[options.field].rstrip('.').split('.')
    short_name = '.'.join(labels[lcount:])
    
    if short_name not in counts:
        counts[short_name] = 0
    
    counts[short_name] += 1

# Print the counts and labels, sorted by count
for name, count in sorted(counts.items(), key=lambda i: i[1]):
    print("%d\t%s" % (count, name))
