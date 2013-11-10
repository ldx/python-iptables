import iptc

table = iptc.Table(iptc.Table.FILTER)
chain = iptc.Chain(table, 'mychain')
rule = iptc.Rule()

for idx, r in enumerate(chain.rules, 1):
    print idx, r.src, r.dst
