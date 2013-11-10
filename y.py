import gc
import iptc
import time

print "Running..."

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
while True:
    for rule in chain.rules:
        print rule.target.name
    print "garbage", gc.garbage
    time.sleep(1)
