#!/usr/bin/env python

import iptc

chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
for r in chain.rules:
    print r
