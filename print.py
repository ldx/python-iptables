#!/usr/bin/env python

import iptc

table = iptc.Table(iptc.Table.FILTER)
for chain in table.chains:
    print "======================="
    print "Chain ", chain.name
    for rule in chain.rules:
        print "Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", \
              rule.dst, "in:", rule.in_interface, "out:", rule.out_interface,
        print "Matches:",
        for match in rule.matches:
            print match.name,
        print "Target:",
        print rule.target.name
print "======================="
