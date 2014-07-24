#!/usr/bin/env python

import iptc

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, "INPUT")
i = 0
while True:
    for rule in chain.rules:
        pass
    i += 1
    if i % 100 == 0:
        print i
