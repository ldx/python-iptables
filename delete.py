#!/usr/bin/env python

import iptc
import time

table = iptc.Table('nat')
chain = iptc.Chain(table, 'PREROUTING')
for port in ['8080', '9090', '10101']:
    rule = iptc.Rule()
    rule.position = 1
    rule.dst = "127.0.0.1"
    rule.protocol = "udp"
    rule.dport = port
    target = rule.create_target("DNAT")
    target.to_destination = '127.0.0.0:' + port
    chain.insert_rule(rule)
#table.commit()
#table.refresh()

time.sleep(3)

table.autocommit = False
print "deleting ", len(chain.rules), "rules from", table.name, "/", chain.name
rules = chain.rules
for rule in rules:
    chain.delete_rule(rule)
table.commit()
table.refresh()
