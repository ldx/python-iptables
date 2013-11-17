Introduction
============

About python-iptables
---------------------

**Iptables** is the tool that is used to manage **netfilter**, the
standard packet filtering and manipulation framework under Linux. As the
iptables manpage puts it:

> Iptables is used to set up, maintain, and inspect the tables of IPv4
> packet filter rules in the Linux kernel. Several different tables may
> be defined.
>
> Each table contains a number of built-in chains and may also contain
> user- defined chains.
>
> Each chain is a list of rules which can match a set of packets. Each
> rule specifies what to do with a packet that matches. This is called a
> target, which may be a jump to a user-defined chain in the same table.

`Python-iptables` provides a pythonesque wrapper via python bindings to
iptables under Linux. Interoperability with iptables is achieved via
using the iptables C libraries (`libiptc`, `libxtables`, and the
iptables extensions), not calling the iptables binary and parsing its
output. It is meant primarily for dynamic and/or complex routers and
firewalls, where rules are often updated or changed, or Python programs
wish to interface with the Linux iptables framework..

![buildstatus](https://travis-ci.org/ldx/python-iptables.png?branch=master)

Installing via pip
------------------

The usual way:

    pip install --upgrade python-iptables

Compiling from source
---------------------

First make sure you have iptables installed (most Linux distributions
install it by default). `Python-iptables` needs the shared libraries
`libiptc.so` and `libxtables.so` coming with iptables, they are
installed in `/lib` on Ubuntu.

You can compile `python-iptables` in the usual distutils way:

    % cd python-iptables
    % python setup.py build

If you like, `python-iptables` can also be installed into a
`virtualenv`:

    % mkvirtualenv python-iptables
    % python setup.py install

If you install `python-iptables` as a system package, make sure the
directory where `distutils` installs shared libraries is in the dynamic
linker's search path (it's in `/etc/ld.so.conf` or in one of the files
in the folder `/etc/ld.co.conf.d`). Under Ubuntu `distutils` by default
installs into `/usr/local/lib`.

Now you can run the tests:

    % sudo PATH=$PATH ./test.py
    WARNING: this test will manipulate iptables rules.
    Don't do this on a production machine.
    Would you like to continue? y/n y
    [...]

The `PATH=$PATH` part is necessary after `sudo` if you have installed
into a `virtualenv`, since `sudo` will reset your environment to a
system setting otherwise..

Once everything is in place you can fire up python to check whether the
package can be imported:

    % sudo PATH=$PATH python
    >>> import iptc
    >>>

Of course you need to be root to be able to use iptables.

What is supported
-----------------

The basic iptables framework and all the match/target extensions are
supported by `python-iptables`, including IPv4 and IPv6 ones. All IPv4
and IPv6 tables are supported as well.

Full documentation with API reference is available
[here](http://ldx.github.com/python-iptables/).

Examples
========

Rules
-----

In `python-iptables`, you usually first create a rule, and set any
source/destination address, in/out interface and protocol specifiers,
for example:

    >>> import iptc
    >>> rule = iptc.Rule()
    >>> rule.in_interface = "eth0"
    >>> rule.src = "192.168.1.0/255.255.255.0"
    >>> rule.protocol = "tcp"

This creates a rule that will match TCP packets coming in on eth0, with
a source IP address of 192.168.1.0/255.255.255.0.

A rule may contain matches and a target. A match is like a filter
matching certain packet attributes, while a target tells what to do with
the packet (drop it, accept it, transform it somehow, etc). One can
create a match or target via a Rule:

    >>> rule = iptc.Rule()
    >>> m = rule.create_match("tcp")
    >>> t = rule.create_target("DROP")

Match and target parameters can be changed after creating them. It is
also perfectly valid to create a match or target via instantiating them
with their constructor, but you still need a rule and you have to add
the matches and the target to their rule manually:

    >>> rule = iptc.Rule()
    >>> match = iptc.Match(rule, "tcp")
    >>> target = iptc.Target(rule, "DROP")
    >>> rule.add_match(match)
    >>> rule.target = target

Any parameters a match or target might take can be set via the
attributes of the object. To set the destination port for a TCP match:

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

When you are ready constructing your rule, add them to the chain you
want it to show up in:

    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> chain.insert_rule(rule)

This will put your rule into the INPUT chain in the filter table.

Chains and tables
-----------------

You can of course also check what a rule's source/destination address,
in/out inteface etc is. To print out all rules in the FILTER table:

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

As you see in the code snippet above, rules are organized into chains,
and chains are in tables. You have a fixed set of tables; for IPv4:

-   FILTER,
-   NAT,
-   MANGLE and
-   RAW.

For IPv6 the tables are:

-   FILTER,
-   MANGLE,
-   RAW and
-   SECURITY.

To access a table:

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> print table.name
    filter

To create a new chain in the FILTER table:

    >>> import iptc
    >>> table = iptc.Table(iptc.Table.FILTER)
    >>> chain = table.create_chain("testchain")

    $ sudo iptables -L -n
    [...]
    Chain testchain (0 references)
    target     prot opt source               destination

To access an existing chain:

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

There are basic targets, such as `DROP` and `ACCEPT`. E.g. to reject
packets with source address `127.0.0.1/255.0.0.0` coming in on any of
the `eth` interfaces:

    >>> import iptc
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    >>> rule = iptc.Rule()
    >>> rule.in_interface = "eth+"
    >>> rule.src = "127.0.0.1/255.0.0.0"
    >>> target = iptc.Target(rule, "DROP")
    >>> rule.target = target
    >>> chain.insert_rule(rule)

To instantiate a target or match, we can either create an object like
above, or use the `rule.create_target(target_name)` and
`rule.create_match(match_name)` methods. For example, in the code above
target could have been created as:

    >>> target = rule.create_target("DROP")

instead of:

    >>> target = iptc.Target(rule, "DROP")
    >>> rule.target = target

The former also adds the match or target to the rule, saving a call.

Another example, using a target which takes parameters. Let's mark
packets going to `192.168.1.2` UDP port `1234` with `0xffff`:

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

Matches are optional (specifying a target is mandatory). E.g. to insert
a rule to NAT TCP packets going out via `eth0`:

    >>> import iptc
    >>> chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
    >>> rule = iptc.Rule()
    >>> rule.protocol = "tcp"
    >>> rule.out_interface = "eth0"
    >>> target = iptc.Target(rule, "MASQUERADE")
    >>> target.to_ports = "1234"
    >>> rule.target = target
    >>> chain.insert_rule(rule)

Here only the properties of the rule decide whether the rule will be
applied to a packet.

Matches are optional, but we can add multiple matches to a rule. In the
following example we will do that, using the `iprange` and the `tcp`
matches:

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

This is the `python-iptables` equivalent of the following iptables
command:

    # iptables -A INPUT -p tcp –destination-port 22 -m iprange –src-range 192.168.1.100-192.168.1.200 –dst-range 172.22.33.106 -j DROP
