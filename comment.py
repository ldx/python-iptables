#!/usr/bin/env python

import gc
import sys
import iptc

#rule = iptc.Rule()
#rule.src = "127.0.0.1"
#rule.protocol = "udp"
#rule.target = rule.create_target("ACCEPT")
#
#match = rule.create_match("comment")
#match.comment = "this is a test comment"

chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
#chain.insert_rule(rule)

while True:
    for r in chain.rules:
        c = r.matches[0].comment
        print >> sys.stderr, "comment", c
    #print >> sys.stderr, "garbage", gc.garbage
    #print >> sys.stderr, "buffers", iptc.BUFFERS
    #print >> sys.stderr, len(iptc.BUFFERS)
