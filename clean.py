#!/usr/bin/env python

import iptc

for name in iptc.Table.ALL:
    table = iptc.Table(name)
    table.autocommit = False
    for chain in table.chains:
        if chain.name.startswith('iptc_'):
            print "Removing", chain.name
            table.delete_chain(chain)
    table.commit()
    table.refresh()

for name in iptc.Table6.ALL:
    table = iptc.Table6(name)
    table.autocommit = False
    for chain in table.chains:
        if chain.name.startswith('iptc_'):
            print "Removing", chain.name
            table.delete_chain(chain)
    table.commit()
    table.refresh()
