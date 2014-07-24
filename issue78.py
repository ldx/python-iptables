#!/usr/bin/env python

import sys
import iptc

chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

for r in chain.rules:
    c = r.matches[0].comment
    print >> sys.stderr, "comment", c
