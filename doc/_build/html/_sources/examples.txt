Examples
========

Simple rule with standard target
--------------------------------

Reject packets with source address ``127.0.0.1/255.0.0.0`` coming in on any of
the eth interfaces:

    >>> import iptc
    >>> chain = iptc.Chain(iptc.TABLE_FILTER, "INPUT")
    >>> rule = iptc.Rule()
    >>> rule.in_interface = "eth+"
    >>> rule.src = "127.0.0.1/255.0.0.0"
    >>> target = iptc.Target(rule, "DROP")
    >>> rule.target = target
    >>> chain.insert_rule(rule)

Simple rule not using any match extensions
------------------------------------------

Inserting a rule to NAT TCP packets going out via ``eth0``:

    >>> import iptc
    >>> chain = iptc.Chain(iptc.TABLE_NAT, "POSTROUTING")
    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> rule.out_interface = "eth0"
    >>> target = iptc.Target(rule, "MASQUERADE")
    >>> target.to_ports = "1234"
    >>> rule.target = target
    >>> chain.insert_rule(rule)

Rule using the udp match extension
----------------------------------

Mark packets going to ``192.168.1.2`` UDP port ``1234`` with ``0xffff``:

    >>> import iptc
    >>> chain = iptc.Chain(iptc.TABLE_MANGLE, "PREROUTING")
    >>> rule = iptc.Rule()
    >>> rule.dst = "192.168.1.2"
    >>> rule.protocol = "udp"
    >>> match = iptc.Match(rule, "udp")
    >>> match.dport = "1234"
    >>> rule.add_match(match)
    >>> target = iptc.Target(rule, "MARK", revision=2) # latest revision
    >>> target.set_mark = "0xffff"
    >>> rule.target = target
    >>> chain.insert_rule(rule)
