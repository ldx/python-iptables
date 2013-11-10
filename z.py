#!/usr/bin/env python

import iptc
import time
import sys

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

while True:
    start = time.time()
    for rule in chain.rules:
        pass
    end = time.time()
    print >> sys.stderr, "%f" % (end - start)
    time.sleep(1)
