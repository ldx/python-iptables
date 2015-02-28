Examples
========

Rules
-----

In ``python-iptables``, you usually first create a rule, and set any
source/destination address, in/out interface and protocol specifiers, for
example::

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
target via a Rule::

    >>> rule = iptc.Rule()
    >>> m = rule.create_match("tcp")
    >>> t = rule.create_target("DROP")

Match and target parameters can be changed after creating them. It is also
perfectly valid to create a match or target via instantiating them with
their constructor, but you still need a rule and you have to add the matches
and the target to their rule manually::

    >>> rule = iptc.Rule()
    >>> match = iptc.Match(rule, "tcp")
    >>> target = iptc.Target(rule, "DROP")
    >>> rule.add_match(match)
    >>> rule.target = target

Any parameters a match or target might take can be set via the attributes of
the object. To set the destination port for a TCP match::

    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> match = rule.create_match("tcp")
    >>> match.dport = "80"

To set up a rule that matches packets marked with 0xff::

    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> match = rule.create_match("mark")
    >>> match.mark = "0xff"

Parameters are always strings. You can supply any string as the parameter
value, but note that most extensions validate their parameters. For example
this::

    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> rule.target = iptc.Target(rule, "ACCEPT")
    >>> match = iptc.Match(rule, "state")
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> match.state = "RELATED,ESTABLISHED"
    >>> rule.add_match(match)
    >>> chain.insert_rule(rule)

will work. However, if you change the `state` parameter::

    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> rule.target = iptc.Target(rule, "ACCEPT")
    >>> match = iptc.Match(rule, "state")
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> match.state = "RELATED,ESTABLISHED,FOOBAR"
    >>> rule.add_match(match)
    >>> chain.insert_rule(rule)

``python-iptables`` will throw an exception::

    Traceback (most recent call last):
      File "state.py", line 7, in <module>
        match.state = "RELATED,ESTABLISHED,FOOBAR"
      File "/home/user/Projects/python-iptables/iptc/ip4tc.py", line 369, in __setattr__
        self.parse(name.replace("_", "-"), value)
      File "/home/user/Projects/python-iptables/iptc/ip4tc.py", line 286, in parse
        self._parse(argv, inv, entry)
      File "/home/user/Projects/python-iptables/iptc/ip4tc.py", line 516, in _parse
        ct.cast(self._ptrptr, ct.POINTER(ct.c_void_p)))
      File "/home/user/Projects/python-iptables/iptc/xtables.py", line 736, in new
        ret = fn(*args)
      File "/home/user/Projects/python-iptables/iptc/xtables.py", line 1031, in parse_match
        argv[1]))
    iptc.xtables.XTablesError: state: parameter error -2 (RELATED,ESTABLISHED,FOOBAR)

Certain parameters take a string that optionally consists of multiple words.
The comment match is a good example::

    >>> rule = iptc.Rule()
    >>> rule.src = "127.0.0.1"
    >>> rule.protocol = "udp"
    >>> rule.target = rule.create_target("ACCEPT")
    >>> match = rule.create_match("comment")
    >>> match.comment = "this is a test comment"
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)

Note that this is still just one parameter value.

However, when a match or a target takes multiple parameter values, that needs
to be passed in as a list. Let's assume you have created and set up an
``ipset`` called ``blacklist`` via the ``ipset`` command. To create a rule
with a match for this set::

    >>> rule = iptc.Rule()
    >>> m = rule.create_match("set")
    >>> m.match_set = ['blacklist', 'src']

Note how this time a list was used for the parameter value, since the ``set``
match ``match_set`` parameter expects two values. See the ``iptables``
manpages to find out what the extensions you use expect. See ipset_ for more
information.

.. _ipset: http://ipset.netfilter.org/

When you are ready constructing your rule, add them to the chain you want it
to show up in::

    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)

This will put your rule into the INPUT chain in the filter table.

Chains and tables
-----------------

You can of course also check what a rule's source/destination address,
in/out inteface etc is. To print out all rules in the FILTER table::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> for chain in table.chains:
    >>>     print "======================="
    >>>     print "Chain ", chain.name
    >>>     for rule in chain.rules:
    >>>         print "Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", \
    >>>               rule.dst, "in:", rule.in_interface, "out:", rule.out_interface,
    >>>         print "Matches:",
    >>>         for match in rule.matches:
    >>>             print match.name,
    >>>         print "Target:",
    >>>         print rule.target.name
    >>> print "======================="

As you see in the code snippet above, rules are organized into chains, and
chains are in tables. You have a fixed set of tables; for IPv4::

* FILTER,
* NAT,
* MANGLE and
* RAW.

For IPv6 the tables are::

* FILTER,
* MANGLE,
* RAW and
* SECURITY.

To access a table::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> print table.name
    filter

To create a new chain in the FILTER table::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = table.create_chain("testchain")

    $ sudo iptables -L -n
    [...]
    Chain testchain (0 references)
    target     prot opt source               destination

To access an existing chain::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = iptc.Chain(table, "INPUT")
    >>> chain.name
    'INPUT'
    >>> len(chain.rules)
    10
    >>>

More about matches and targets
------------------------------

There are basic targets, such as ``DROP`` and ``ACCEPT``. E.g. to reject
packets with source address ``127.0.0.1/255.0.0.0`` coming in on any of the
``eth`` interfaces::

    >>> import iptc
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> rule = iptc.Rule()
    >>> rule.in_interface = "eth+"
    >>> rule.src = "127.0.0.1/255.0.0.0"
    >>> target = iptc.Target(rule, "DROP")
    >>> rule.target = target
    >>> chain.insert_rule(rule)

To instantiate a target or match, we can either create an object like above,
or use the ``rule.create_target(target_name)`` and
``rule.create_match(match_name)`` methods. For example, in the code above
target could have been created as::

    >>> target = rule.create_target("DROP")

instead of::

    >>> target = iptc.Target(rule, "DROP")
    >>> rule.target = target

The former also adds the match or target to the rule, saving a call.

Another example, using a target which takes parameters. Let's mark packets
going to ``192.168.1.2`` UDP port ``1234`` with ``0xffff``::

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

Matches are optional (specifying a target is mandatory). E.g. to insert a rule
to NAT TCP packets going out via ``eth0``::

    >>> import iptc
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> rule.out_interface = "eth0"
    >>> target = iptc.Target(rule, "MASQUERADE")
    >>> target.to_ports = "1234"
    >>> rule.target = target
    >>> chain.insert_rule(rule)

Here only the properties of the rule decide whether the rule will be applied
to a packet.

Matches are optional, but we can add multiple matches to a rule. In the
following example we will do that, using the ``iprange`` and the ``tcp``
matches::

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
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)

This is the ``python-iptables`` equivalent of the following iptables command::

    # iptables -A INPUT -p tcp –destination-port 22 -m iprange –src-range 192.168.1.100-192.168.1.200 –dst-range 172.22.33.106 -j DROP

You can of course negate matches, just like when you use ``!`` in front of a
match with iptables. For example::

    >>> import iptc
    >>> rule = iptc.Rule()
    >>> match = iptc.Match(rule, "mac")
    >>> match.mac_source = "!00:11:22:33:44:55"
    >>> rule.add_match(match)
    >>> rule.target = iptc.Target(rule, "ACCEPT")
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)

This results in::

    $ sudo iptables -L -n
    Chain INPUT (policy ACCEPT)
    target     prot opt source               destination
    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            MAC ! 00:11:22:33:44:55

    Chain FORWARD (policy ACCEPT)
    target     prot opt source               destination

    Chain OUTPUT (policy ACCEPT)
    target     prot opt source               destination

Counters
--------
You can query rule and chain counters, e.g.::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = iptc.Chain(table, 'OUTPUT')
    >>> for rule in chain.rules:
    >>>         (packets, bytes) = rule.get_counters()
    >>>         print packets, bytes

However, the counters are only refreshed when the underlying low-level
iptables connection is refreshed in ``Table`` via ``table.refresh()``. For
example::

    >>> import time, sys
    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = iptc.Chain(table, 'OUTPUT')
    >>> for rule in chain.rules:
    >>>         (packets, bytes) = rule.get_counters()
    >>>         print packets, bytes
    >>> print "Please send some traffic"
    >>> sys.stdout.flush()
    >>> time.sleep(3)
    >>> for rule in chain.rules:
    >>>         # Here you will get back the same counter values as above
    >>>         (packets, bytes) = rule.get_counters()
    >>>         print packets, bytes

This will show you the same counter values even if there was traffic hitting
your rules. You have to refresh your table to get update your counters::

    >>> import time, sys
    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = iptc.Chain(table, 'OUTPUT')
    >>> for rule in chain.rules:
    >>>         (packets, bytes) = rule.get_counters()
    >>>         print packets, bytes
    >>> print "Please send some traffic"
    >>> sys.stdout.flush()
    >>> time.sleep(3)
    >>> table.refresh()  # Here: refresh table to update rule counters
    >>> for rule in chain.rules:
    >>>         (packets, bytes) = rule.get_counters()
    >>>         print packets, bytes

What is more, if you add::

    iptables -A OUTPUT -p tcp --sport 80
    iptables -A OUTPUT -p tcp --sport 22

you can query rule and chain counters together with the protocol and sport(or
dport), e.g.::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = iptc.Chain(table, 'OUTPUT')
    >>> for rule in chain.rules:
    >>>         for match in rule.matches:
    >>>             (packets, bytes) = rule.get_counters()
    >>>             print packets, bytes, match.name, match.sport

Autocommit
----------
``Python-iptables`` by default automatically performs an iptables commit after
each operation. That is, after you add a rule in ``python-iptables``, that
will take effect immediately.

It may happen that you want to batch together certain operations. A typical
use case is traversing a chain and removing rules matching a specific
criteria. If you do this with autocommit enabled, after the first delete
operation, your chain's state will change and you have to restart the
traversal. You can do something like this::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> removed = True
    >>> chain = iptc.Chain(table, "FORWARD")
    >>> while removed == True:
    >>>     removed = False
    >>>     for rule in chain.rules:
    >>>         if rule.out_interface and "eth0" in rule.out_interface:
    >>>             chain.delete_rule(rule)
    >>>             removed = True
    >>>             break

This is clearly not ideal and the code is not very readable. An alternative is
to disable autocommits, traverse the chain, removing one or more rules, than
commit it::

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> table.autocommit = False
    >>> chain = iptc.Chain(table, "FORWARD")
    >>> for rule in chain.rules:
    >>>     if rule.out_interface and "eth0" in rule.out_interface:
    >>>         chain.delete_rule(rule)
    >>> table.commit()
    >>> table.autocommit = True

The drawback is that `Table` is a singleton, and if you disable autocommit, it
will be disabled for all instances of that `Table`.
