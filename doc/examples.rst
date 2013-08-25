Examples
========

Introduction
------------

In ``python-iptables``, you usually first create a rule, and set any
source/destination address, in/out interface and protocol specifiers, for
example:

    >>> import iptc
    >>> rule = iptc.Rule()
    >>> rule.in_interface = "eth0"
    >>> rule.src = "192.168.1.0/255.255.255.0"
    >>> rule.protocol = "tcp"

This creates a rule that will match TCP packets coming in on eth0, with a
source IP address of 192.168.1.0/255.255.255.0.

A rule may contain matches and a target. A match is like a filter matching
certain packet attributes, while a target tells what to do with the packet
(drop it, accept it, transform it somehow, etc). One can create a match or
target via a Rule:

    >>> rule = iptc.Rule()
    >>> m = rule.create_match("tcp")
    >>> t = rule.create_target("DROP")

Match and target parameters can be changed after creating them. It is also
perfectly valid to create a match or target via instantiating them with
their constructor, but you still need a rule and you have to add the matches
and the target to their rule manually:

    >>> rule = iptc.Rule()
    >>> match = iptc.Match(rule, "tcp")
    >>> target = iptc.Target(rule, "DROP")
    >>> rule.add_match(match)
    >>> rule.target = target

Any parameters a match or target might take can be set via the attributes of
the object. To set the destination port for a TCP match:

    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> match = rule.create_match("tcp")
    >>> match.dport = "80"

To set up a rule that matches packets marked with 0xff:

    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> match = rule.create_match("mark")
    >>> match.mark = "0xff"

Parameters are always strings.

When you are ready constructing your rule, add them to the chain you want it
to show up in:

    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)

This will put your rule into the INPUT chain in the filter table.

Simple rule with standard target
--------------------------------

Reject packets with source address ``127.0.0.1/255.0.0.0`` coming in on any of
the eth interfaces:

    >>> import iptc
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
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
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
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
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE), "PREROUTING")
    >>> rule = iptc.Rule()
    >>> rule.dst = "192.168.1.2"
    >>> rule.protocol = "udp"
    >>> match = iptc.Match(rule, "udp")
    >>> match.dport = "1234"
    >>> rule.add_match(match)
    >>> target = iptc.Target(rule, "MARK")
    >>> target.set_mark = "0xffff"
    >>> rule.target = target
    >>> chain.insert_rule(rule)

Multiple matches with iprange
-----------------------------

Now we will add multiple matches to a rule. This one is the
``python-iptables`` equivalent of the following iptables command:

# iptables -A INPUT -p tcp –destination-port 22 -m iprange –src-range 192.168.1.100-192.168.1.200 –dst-range 172.22.33.106 -j DROP

    >>> import iptc
    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> match = iptc.Match(rule, "tcp")
    >>> match.dport = "22"
    >>> rule.add_match(match)
    >>> match = iptc.Match(rule, "iprange")
    >>> match.src_range = "192.168.1.100-192.168.1.200"
    >>> match.dst_range = "172.22.33.106"
    >>> rule.add_match(match)
    >>> rule.target = iptc.Target(rule, "DROP")
    >>> chain = iptc.Chain(iptc.Table.(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)
