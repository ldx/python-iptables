import iptc
import time

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
while True:
    for rule in chain.rules:
        pass
    print "Sleeping..."
