Introduction
============

About python-iptables
---------------------

**Iptables** is the tool that is used to manage **netfilter**, the standard
packet filtering and manipulation framework under Linux.  As the iptables
manpage puts it:

    Iptables  is used to set up, maintain, and inspect the tables of IPv4
    packet filter rules in the Linux kernel.  Several different tables may be
    defined.

    Each  table  contains a number of built-in chains and may also contain
    user- defined chains.

    Each chain is a list of rules which can match a set of packets.   Each
    rule specifies what to do with a packet that matches.  This is called a
    `target`, which may be a jump to a user-defined chain in the same table.

``Python-iptables`` provides python bindings to iptables under Linux.
Interoperability with iptables is achieved via using the iptables C libraries
(``libiptc``, ``libxtables``, and the iptables extensions), not calling the
iptables binary and parsing its output.

Compiling and installing
------------------------

First make sure you have iptables installed (most Linux distributions install
it by default). ``Python-iptables`` needs the shared libraries ``libiptc.so``
and ``libxtables.so`` coming with iptables, they are installed in ``/lib`` on
Ubuntu.

You can compile ``python-iptables`` in the usual distutils way::

    % cd python-iptables
    % python setup.py build

If you like, ``python-iptables`` can also be installed into a ``virtualenv``::

    % mkvirtualenv python-iptables
    % python setup.py install

If you install ``python-iptables`` as a system package, make sure the
directory where ``distutils`` installs shared libraries is in the dynamic
linker's search path (it's in ``/etc/ld.so.conf`` or in one of the files in
the folder ``/etc/ld.co.conf.d``).  Under Ubuntu ``distutils`` by default
installs into ``/usr/local/lib``.

Now you can run the tests::

    % sudo PATH=$PATH ./test.py
    WARNING: this test will manipulate iptables rules.
    Don't do this on a production machine.
    Would you like to continue? y/n y
    test_table6 (iptc.test.test_iptc.TestTable6) ... ok
    test_refresh (iptc.test.test_iptc.TestTable) ... ok
    test_table (iptc.test.test_iptc.TestTable) ... ok
    test_builtin_chain (iptc.test.test_iptc.TestChain) ... ok
    test_chain (iptc.test.test_iptc.TestChain) ... ok
    test_chain_counters (iptc.test.test_iptc.TestChain) ... ok
    test_chain_policy (iptc.test.test_iptc.TestChain) ... ok
    test_chains (iptc.test.test_iptc.TestChain) ... ok
    test_create_chain (iptc.test.test_iptc.TestChain) ... ok
    test_is_chain (iptc.test.test_iptc.TestChain) ... ok
    test_rule_address (iptc.test.test_iptc.TestRule6) ... ok
    test_rule_compare (iptc.test.test_iptc.TestRule6) ... ok
    test_rule_interface (iptc.test.test_iptc.TestRule6) ... ok
    test_rule_iterate (iptc.test.test_iptc.TestRule6) ... ok
    test_rule_protocol (iptc.test.test_iptc.TestRule6) ... ok
    test_rule_standard_target (iptc.test.test_iptc.TestRule6) ... ok
    test_rule_address (iptc.test.test_iptc.TestRule) ... ok
    test_rule_compare (iptc.test.test_iptc.TestRule) ... ok
    test_rule_fragment (iptc.test.test_iptc.TestRule) ... ok
    test_rule_interface (iptc.test.test_iptc.TestRule) ... ok
    test_rule_iterate (iptc.test.test_iptc.TestRule) ... ok
    test_rule_protocol (iptc.test.test_iptc.TestRule) ... ok
    test_rule_standard_target (iptc.test.test_iptc.TestRule) ... ok

    ----------------------------------------------------------------------
    Ran 23 tests in 0.013s

    OK
    test_match_compare (iptc.test.test_matches.TestMatch) ... ok
    test_match_create (iptc.test.test_matches.TestMatch) ... ok
    test_match_parameters (iptc.test.test_matches.TestMatch) ... ok
    test_udp_insert (iptc.test.test_matches.TestXTUdpMatch) ... ok
    test_udp_port (iptc.test.test_matches.TestXTUdpMatch) ... ok
    test_mark (iptc.test.test_matches.TestXTMarkMatch) ... ok
    test_mark_insert (iptc.test.test_matches.TestXTMarkMatch) ... ok
    test_limit (iptc.test.test_matches.TestXTLimitMatch) ... ok
    test_limit_insert (iptc.test.test_matches.TestXTLimitMatch) ... ok
    test_comment (iptc.test.test_matches.TestCommentMatch) ... ok
    test_iprange (iptc.test.test_matches.TestIprangeMatch) ... ok
    test_iprange_tcpdport (iptc.test.test_matches.TestIprangeMatch) ... ok

    ----------------------------------------------------------------------
    Ran 12 tests in 0.024s

    OK
    test_target_compare (iptc.test.test_targets.TestTarget) ... ok
    test_target_create (iptc.test.test_targets.TestTarget) ... ok
    test_target_parameters (iptc.test.test_targets.TestTarget) ... ok
    test_insert (iptc.test.test_targets.TestXTClusteripTarget) ... ok
    test_mode (iptc.test.test_targets.TestXTClusteripTarget) ... ok
    test_insert (iptc.test.test_targets.TestIPTRedirectTarget) ... ok
    test_mode (iptc.test.test_targets.TestIPTRedirectTarget) ... ok
    test_insert (iptc.test.test_targets.TestXTTosTarget) ... ok
    test_mode (iptc.test.test_targets.TestXTTosTarget) ... ok
    test_insert (iptc.test.test_targets.TestIPTMasqueradeTarget) ... ok
    test_mode (iptc.test.test_targets.TestIPTMasqueradeTarget) ... ok

    ----------------------------------------------------------------------
    Ran 11 tests in 0.015s

    OK

The ``PATH=$PATH`` part is necessary after ``sudo`` if you have installed into
a ``virtualenv``, since ``sudo`` will reset your environment to a system
setting otherwise..

Once everything is in place you can fire up python to check whether the
package can be imported::

    % sudo PATH=$PATH python
    >>> import iptc
    >>>

Of course you need to be root to be able to use iptables.

What is supported
-----------------

The basic iptables framework and all the match/target extensions are supported
by ``python-iptables``, including IPv4 and IPv6 ones. All IPv4 and IPv6 tables
are supported as well.

Contact
-------

ldx (at) nilvec.com

http://nilvec.com
