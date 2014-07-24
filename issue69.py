#!/usr/bin/env python

import os
import iptc

#os.system('iptables -t filter -A FORWARD -o vlan93 -d 5.5.5.5 -j ACCEPT')

rule = iptc.Rule()
rule.out_interface = 'vlan93'
rule.dst = '5.5.5.5'
rule.target = iptc.Target(rule, "ACCEPT")
print
print "in", rule.entry.ip.iniface, "inmask", rule.entry.ip.iniface_mask
print "out", rule.entry.ip.outiface, "outmask", rule.entry.ip.outiface_mask
print
tbl = iptc.Table('filter')
chain = iptc.Chain(tbl, 'FORWARD')
for r in chain.rules:
    print
    print "in", r.entry.ip.iniface, "inmask", r.entry.ip.iniface_mask
    print "out", r.entry.ip.outiface, "outmask", r.entry.ip.outiface_mask
    for x in r.entry.ip.outiface_mask:
        print "%02x" % ord(x),
    print
chain.delete_rule(rule)
