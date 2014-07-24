import iptc

table = iptc.Table6(iptc.Table6.FILTER)
chain = iptc.Chain(table, "INPUT")
print table.name, chain.name

# ip6tables -I INPUT -i eth0 -p icmpv6 -m icmp6 --icmpv6-type echo-request -j ACCEPT
rule6 = iptc.Rule6()
rule6.in_interface = 'eth0'
rule6.protocol = 'icmpv6'  # icmpv6 according to ip6tables
match = rule6.create_match('icmp6')
match.icmpv6_type = 'echo-request'  # icmpv6_type according to ip6tables
target = rule6.create_target('ACCEPT')
chain.insert_rule(rule6)
print rule6.matches[0].name
print rule6.target.name
table.refresh()
for r in chain.rules:
    print r
