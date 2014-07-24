#!/usr/bin/python

import iptc

while True:
    chain_name = 'FORWARD'
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
    print chain.name
