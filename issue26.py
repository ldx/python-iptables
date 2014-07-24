#!/usr/bin/env python

import iptc

rule = iptc.Rule()
rule.protocol = "tcp"
rule.dst = "1.1.1.1"
match = iptc.Match(rule, "tcp")
match.syn = "1"
rule.add_match(match)
rule.target = iptc.Target(rule, "ACCEPT")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "iptc_test_chain")
iptc.Table(iptc.Table.FILTER).create_chain(chain)
chain.insert_rule(rule)
try:
    print chain.rules[0].matches[0].name
except:
    print "error parsing rule"

chain.delete_rule(rule)
iptc.Table(iptc.Table.FILTER).delete_chain(chain)
