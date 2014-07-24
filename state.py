#!/usr/bin/env python

import iptc

table = iptc.Table('filter')
#table.autocommit = False
chain = iptc.Chain(table, 'INPUT')
rule = iptc.Rule()
rule.position = 1
rule.dst = "127.0.0.1"
rule.protocol = "udp"
rule.dport = "8080"
target = rule.create_target("ACCEPT")
match = rule.create_match("state")
match.state = "RELATED,ESTABLISHED"
print "inserting"
chain.insert_rule(rule)
print "inserting ok"
#table.commit()
#table.refresh()

rule = chain.rules[0]
m = rule.matches[0]
print m.name
