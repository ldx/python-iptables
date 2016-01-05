# -*- coding: utf-8 -*-

import unittest
import iptc


is_table_available = iptc.is_table_available
is_table6_available = iptc.is_table6_available


def _check_chains(testcase, *chains):
    for chain in chains:
        if chain is None:
            continue
        for ch in [c for c in chains if c != chain and c is not None]:
            testcase.assertNotEquals(id(chain), id(ch))


class TestTable6(unittest.TestCase):
    def setUp(self):
        self.autocommit = iptc.Table(iptc.Table.FILTER).autocommit

    def tearDown(self):
        iptc.Table(iptc.Table.FILTER, self.autocommit)

    def test_table6(self):
        filt = None
        if is_table6_available(iptc.Table6.FILTER):
            filt = iptc.Table6("filter")
            self.assertEquals(id(filt), id(iptc.Table6(iptc.Table6.FILTER)))
        security = None
        if is_table6_available(iptc.Table6.SECURITY):
            security = iptc.Table6("security")
            self.assertEquals(id(security),
                              id(iptc.Table6(iptc.Table6.SECURITY)))
        mangle = None
        if is_table6_available(iptc.Table6.MANGLE):
            mangle = iptc.Table6("mangle")
            self.assertEquals(id(mangle), id(iptc.Table6(iptc.Table6.MANGLE)))
        raw = None
        if is_table6_available(iptc.Table6.RAW):
            raw = iptc.Table6("raw")
            self.assertEquals(id(raw), id(iptc.Table6(iptc.Table6.RAW)))
        _check_chains(self, filt, security, mangle, raw)

    def test_table6_autocommit(self):
        table = iptc.Table(iptc.Table.FILTER, False)
        self.assertEquals(table.autocommit, False)

        rule = iptc.Rule()
        rule.src = "1.2.3.4"
        rule.dst = "2.3.4.5"
        rule.protocol = "tcp"
        self.assertEquals(table.autocommit, False)

        rule.create_target('DROP')
        self.assertEquals(table.autocommit, False)

        match = rule.create_match('tcp')
        match.dport = "80:90"
        self.assertEquals(table.autocommit, False)


class TestTable(unittest.TestCase):
    def setUp(self):
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_chain")

        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        iptc.Table(iptc.Table.FILTER).flush()

    def test_table(self):
        filt = None
        if is_table_available(iptc.Table.FILTER):
            filt = iptc.Table("filter")
            self.assertEquals(id(filt), id(iptc.Table(iptc.Table.FILTER)))
        nat = None
        if is_table_available(iptc.Table.NAT):
            nat = iptc.Table("nat")
            self.assertEquals(id(nat), id(iptc.Table(iptc.Table.NAT)))
        mangle = None
        if is_table_available(iptc.Table.MANGLE):
            mangle = iptc.Table("mangle")
            self.assertEquals(id(mangle), id(iptc.Table(iptc.Table.MANGLE)))
        raw = None
        if is_table_available(iptc.Table.RAW):
            raw = iptc.Table("raw")
            self.assertEquals(id(raw), id(iptc.Table(iptc.Table.RAW)))
        _check_chains(self, filt, nat, mangle, raw)

    def test_refresh(self):
        rule = iptc.Rule()
        match = iptc.Match(rule, "tcp")
        match.dport = "1234"
        rule.add_match(match)
        try:
            self.chain.insert_rule(rule)
            iptc.Table(iptc.Table.FILTER).delete_chain(self.chain)
            self.fail("inserted invalid rule")
        except:
            pass
        iptc.Table(iptc.Table.FILTER).refresh()
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        rule.protocol = "tcp"
        self.chain.insert_rule(rule)
        self.chain.delete_rule(rule)

    def test_flush_user_chains(self):

        chain1 = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                            "iptc_test_flush_chain1")
        chain2 = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                            "iptc_test_flush_chain2")
        iptc.Table(iptc.Table.FILTER).create_chain(chain1)
        iptc.Table(iptc.Table.FILTER).create_chain(chain2)

        rule = iptc.Rule()
        rule.target = iptc.Target(rule, chain2.name)
        chain1.append_rule(rule)

        rule = iptc.Rule()
        rule.target = iptc.Target(rule, chain1.name)
        chain2.append_rule(rule)

        self.assertEquals(len(chain1.rules), 1)
        self.assertEquals(len(chain2.rules), 1)

        filter_table = iptc.Table(iptc.Table.FILTER)
        filter_table.flush()

        self.assertTrue(not filter_table.is_chain(chain1.name))
        self.assertTrue(not filter_table.is_chain(chain2.name))

    def test_flush_builtin(self):
        filter_table = iptc.Table(iptc.Table.FILTER)
        output_rule_count = len(iptc.Chain(filter_table, "OUTPUT").rules)

        rule = iptc.Rule()
        rule.target = iptc.Target(rule, "ACCEPT")

        iptc.Chain(filter_table, "OUTPUT").append_rule(rule)

        self.assertEquals(len(iptc.Chain(filter_table, "OUTPUT").rules),
                          output_rule_count + 1)

        filter_table.flush()

        self.assertEquals(len(iptc.Chain(filter_table, "OUTPUT").rules), 0)


class TestChain(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_chain(self):
        table = iptc.Table(iptc.Table.FILTER)
        input1 = iptc.Chain(table, "INPUT")
        input2 = iptc.Chain(table, "INPUT")
        forward1 = iptc.Chain(table, "FORWARD")
        forward2 = iptc.Chain(table, "FORWARD")
        output1 = iptc.Chain(table, "OUTPUT")
        output2 = iptc.Chain(table, "OUTPUT")
        self.assertEquals(id(input1), id(input2))
        self.assertEquals(id(output1), id(output2))
        self.assertEquals(id(forward1), id(forward2))
        self.assertNotEquals(id(input1), id(output1))
        self.assertNotEquals(id(input1), id(output2))
        self.assertNotEquals(id(input1), id(forward1))
        self.assertNotEquals(id(input1), id(forward2))
        self.assertNotEquals(id(input2), id(output1))
        self.assertNotEquals(id(input2), id(output2))
        self.assertNotEquals(id(input2), id(forward1))
        self.assertNotEquals(id(input2), id(forward2))
        self.assertNotEquals(id(output1), id(forward1))
        self.assertNotEquals(id(output1), id(forward2))
        self.assertNotEquals(id(output2), id(forward1))
        self.assertNotEquals(id(output2), id(forward2))

    def test_is_chain(self):
        if is_table_available(iptc.Table.FILTER):
            table = iptc.Table(iptc.Table.FILTER)
            self.assertTrue(table.is_chain("INPUT"))
            self.assertTrue(table.is_chain("FORWARD"))
            self.assertTrue(table.is_chain("OUTPUT"))

        if is_table_available(iptc.Table.NAT):
            table = iptc.Table(iptc.Table.NAT)
            self.assertTrue(table.is_chain("PREROUTING"))
            self.assertTrue(table.is_chain("POSTROUTING"))
            self.assertTrue(table.is_chain("OUTPUT"))

        if is_table_available(iptc.Table.MANGLE):
            table = iptc.Table(iptc.Table.MANGLE)
            self.assertTrue(table.is_chain("INPUT"))
            self.assertTrue(table.is_chain("PREROUTING"))
            self.assertTrue(table.is_chain("FORWARD"))
            self.assertTrue(table.is_chain("POSTROUTING"))
            self.assertTrue(table.is_chain("OUTPUT"))

        if is_table_available(iptc.Table.RAW):
            table = iptc.Table(iptc.Table.RAW)
            self.assertTrue(table.is_chain("PREROUTING"))
            self.assertTrue(table.is_chain("OUTPUT"))

    def test_builtin_chain(self):
        if is_table_available(iptc.Table.FILTER):
            table = iptc.Table(iptc.Table.FILTER)
            self.assertTrue(table.builtin_chain("INPUT"))
            self.assertTrue(table.builtin_chain("FORWARD"))
            self.assertTrue(table.builtin_chain("OUTPUT"))

        if is_table_available(iptc.Table.NAT):
            table = iptc.Table(iptc.Table.NAT)
            self.assertTrue(table.builtin_chain("PREROUTING"))
            self.assertTrue(table.builtin_chain("POSTROUTING"))
            self.assertTrue(table.builtin_chain("OUTPUT"))

        if is_table_available(iptc.Table.MANGLE):
            table = iptc.Table(iptc.Table.MANGLE)
            self.assertTrue(table.builtin_chain("INPUT"))
            self.assertTrue(table.builtin_chain("PREROUTING"))
            self.assertTrue(table.builtin_chain("FORWARD"))
            self.assertTrue(table.builtin_chain("POSTROUTING"))
            self.assertTrue(table.builtin_chain("OUTPUT"))

        if is_table_available(iptc.Table.RAW):
            table = iptc.Table(iptc.Table.RAW)
            self.assertTrue(table.builtin_chain("PREROUTING"))
            self.assertTrue(table.builtin_chain("OUTPUT"))

    def test_chain_filter(self):
        if is_table_available(iptc.Table.FILTER):
            table = iptc.Table(iptc.Table.FILTER)
            table.autocommit = True
            self.assertTrue(len(table.chains) >= 3)
            for chain in table.chains:
                if chain.name not in ["INPUT", "FORWARD", "OUTPUT"]:
                    self.failIf(chain.is_builtin())

    def test_chain_nat(self):
        if is_table_available(iptc.Table.NAT):
            table = iptc.Table(iptc.Table.NAT)
            table.autocommit = True
            self.assertTrue(len(table.chains) >= 3)
            for chain in table.chains:
                if chain.name not in ["INPUT", "PREROUTING", "POSTROUTING",
                                      "OUTPUT"]:
                    self.failIf(chain.is_builtin())

    def test_chain_mangle(self):
        if is_table_available(iptc.Table.MANGLE):
            table = iptc.Table(iptc.Table.MANGLE)
            table.autocommit = True
            self.assertTrue(len(table.chains) >= 5)
            for chain in table.chains:
                if chain.name not in ["PREROUTING", "POSTROUTING", "INPUT",
                                      "FORWARD", "OUTPUT"]:
                    self.failIf(chain.is_builtin())

    def test_chain_raw(self):
        if is_table_available(iptc.Table.RAW):
            table = iptc.Table(iptc.Table.RAW)
            table.autocommit = True
            self.assertTrue(len(table.chains) >= 2)
            for chain in table.chains:
                if chain.name not in ["PREROUTING", "OUTPUT"]:
                    self.failIf(chain.is_builtin())

    def _get_tables(self):
        tables = []
        if is_table_available(iptc.Table.FILTER):
            tables.append(iptc.Table(iptc.Table.FILTER))
        if is_table_available(iptc.Table.NAT):
            tables.append(iptc.Table(iptc.Table.NAT))
        if is_table_available(iptc.Table.MANGLE):
            tables.append(iptc.Table(iptc.Table.MANGLE))
        if is_table_available(iptc.Table.RAW):
            tables.append(iptc.Table(iptc.Table.RAW))
        return tables

    def test_chain_counters(self):
        tables = self._get_tables()
        for chain in (chain for table in tables for chain in table.chains):
            counters = chain.get_counters()
            fails = 0
            for x in range(3):  # try 3 times
                chain.zero_counters()
                counters = chain.get_counters()
                if counters:   # only built-in chains
                    if counters[0] != 0 or counters[1] != 0:
                        fails += 1
            self.failIf(fails > 2)

    def test_create_chain(self):
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "iptc_test_chain")
        iptc.Table(iptc.Table.FILTER).create_chain(chain)
        self.failUnless(iptc.Table(iptc.Table.FILTER).is_chain(chain))
        iptc.Table(iptc.Table.FILTER).delete_chain(chain)
        self.failIf(iptc.Table(iptc.Table.FILTER).is_chain(chain))

    def test_filter_policy(self):
        if is_table_available(iptc.Table.FILTER):
            table = iptc.Table(iptc.Table.FILTER)
            input_chain = iptc.Chain(table, "INPUT")
            pol = iptc.Policy("DROP")
            input_chain.set_policy(pol)
            rpol = input_chain.get_policy()
            self.assertEquals(id(pol), id(rpol))
            pol = iptc.Policy("ACCEPT")
            input_chain.set_policy(pol)
            rpol = input_chain.get_policy()
            self.assertEquals(id(pol), id(rpol))
            pol = iptc.Policy("RETURN")
            try:
                input_chain.set_policy(pol)
            except iptc.IPTCError:
                pass
            else:
                self.fail("managed to set INPUT policy to RETURN")

    def test_nat_policy(self):
        if is_table_available(iptc.Table.NAT):
            table = iptc.Table(iptc.Table.NAT)
            prerouting_chain = iptc.Chain(table, "PREROUTING")
            pol = iptc.Policy("DROP")
            prerouting_chain.set_policy(pol)
            rpol = prerouting_chain.get_policy()
            self.assertEquals(id(pol), id(rpol))
            pol = iptc.Policy("ACCEPT")
            prerouting_chain.set_policy(pol)
            rpol = prerouting_chain.get_policy()
            self.assertEquals(id(pol), id(rpol))
            pol = iptc.Policy("RETURN")
            try:
                prerouting_chain.set_policy(pol)
            except iptc.IPTCError:
                pass
            else:
                self.fail("managed to set PREROUTING policy to RETURN")

        if is_table_available(iptc.Table.MANGLE):
            table = iptc.Table(iptc.Table.MANGLE)
            forward_chain = iptc.Chain(table, "FORWARD")
            pol = iptc.Policy("DROP")
            forward_chain.set_policy(pol)
            rpol = forward_chain.get_policy()
            self.assertEquals(id(pol), id(rpol))
            pol = iptc.Policy("ACCEPT")
            forward_chain.set_policy(pol)
            rpol = forward_chain.get_policy()
            self.assertEquals(id(pol), id(rpol))
            pol = iptc.Policy("RETURN")
            try:
                forward_chain.set_policy(pol)
            except iptc.IPTCError:
                pass
            else:
                self.fail("managed to set FORWARD policy to RETURN")


class TestRule6(unittest.TestCase):
    def setUp(self):
        self.chain = iptc.Chain(iptc.Table6(iptc.Table6.FILTER),
                                "iptc_test_chain")
        iptc.Table6(iptc.Table6.FILTER).create_chain(self.chain)

    def tearDown(self):
        self.chain.flush()
        self.chain.delete()

    def test_rule_address(self):
        # valid addresses
        rule = iptc.Rule6()
        for addr in ["::/128", "!2000::1/16", "2001::/64", "!2001::1/48"]:
            rule.src = addr
            self.assertEquals(rule.src, addr)
            rule.dst = addr
            self.assertEquals(rule.dst, addr)
        addr = "::1"
        rule.src = addr
        self.assertEquals("::1/128", rule.src)
        rule.dst = addr
        self.assertEquals("::1/128", rule.dst)

        # invalid addresses
        for addr in ["2001:fg::/::", "2001/ffff::", "2001::/-1", "2001::/129",
                     "::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                     "::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:"]:
            try:
                rule.src = addr
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid address %s" % (addr))
            try:
                rule.dst = addr
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid address %s" % (addr))

    def test_rule_interface(self):
        # valid interfaces
        rule = iptc.Rule6()
        for intf in ["eth0", "eth+", "ip6tnl1", "ip6tnl+", "!ppp0", "!ppp+"]:
            rule.in_interface = intf
            self.assertEquals(intf, rule.in_interface)
            rule.out_interface = intf
            self.assertEquals(intf, rule.out_interface)

        # invalid interfaces
        for intf in ["itsaverylonginterfacename"]:
            try:
                rule.out_interface = intf
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid interface name %s" % (intf))
            try:
                rule.in_interface = intf
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid interface name %s" % (intf))

    def test_rule_protocol(self):
        rule = iptc.Rule6()
        for proto in ["tcp", "udp", "icmp", "AH", "ESP", "!TCP", "!UDP",
                      "!ICMP", "!ah", "!esp"]:
            rule.protocol = proto
            self.assertEquals(proto.lower(), rule.protocol)
        for proto in ["", "asdf", "!"]:
            try:
                rule.protocol = proto
            except ValueError:
                pass
            except IndexError:
                pass
            else:
                self.fail("rule accepted invalid protocol %s" % (proto))

    def test_rule_protocol_numeric(self):
        rule = iptc.Rule6()
        rule.protocol = 132
        self.assertEquals(rule.protocol, '132')
        rule.protocol = '!132'
        self.assertEquals(rule.protocol, '!132')

    def test_rule_compare(self):
        r1 = iptc.Rule6()
        r1.src = "::1/128"
        r1.dst = "2001::/8"
        r1.protocol = "tcp"
        r1.in_interface = "wlan+"
        r1.out_interface = "eth1"

        r2 = iptc.Rule6()
        r2.src = "::1/128"
        r2.dst = "2001::/8"
        r2.protocol = "tcp"
        r2.in_interface = "wlan+"
        r2.out_interface = "eth1"

        self.failUnless(r1 == r2)

        r1.src = "::1/ffff::"
        self.failIf(r1 == r2)

    def test_rule_standard_target(self):
        try:
            target = iptc.Target(iptc.Rule(), "jump_to_chain")
        except:
            pass
        else:
            self.fail("target accepted invalid name jump_to_chain")

        rule = iptc.Rule6()
        rule.protocol = "tcp"
        rule.src = "::1"

        target = iptc.Target(rule, "RETURN")
        self.assertEquals(target.name, "RETURN")
        target = iptc.Target(rule, "ACCEPT")
        self.assertEquals(target.name, "ACCEPT")
        target = iptc.Target(rule, "")
        self.assertEquals(target.name, "")
        target.standard_target = "ACCEPT"
        self.assertEquals(target.name, "ACCEPT")
        self.assertEquals(target.standard_target, "ACCEPT")

        target = iptc.Target(rule, self.chain.name)
        rule.target = target

        self.chain.insert_rule(rule)
        self.chain.delete_rule(rule)

    def test_rule_iterate_filter(self):
        if is_table6_available(iptc.Table6.FILTER):
            for r in (rule for chain in iptc.Table6(iptc.Table6.FILTER).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_iterate_raw(self):
        if is_table6_available(iptc.Table6.RAW):
            for r in (rule for chain in iptc.Table6(iptc.Table6.RAW).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_iterate_mangle(self):
        if is_table6_available(iptc.Table6.MANGLE):
            for r in (rule for chain in iptc.Table6(iptc.Table6.MANGLE).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_iterate_security(self):
        if is_table6_available(iptc.Table6.SECURITY):
            for r in (rule for chain in
                      iptc.Table6(iptc.Table6.SECURITY).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_insert(self):
        rules = []

        rule = iptc.Rule6()
        rule.protocol = "tcp"
        rule.src = "::1"
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        self.chain.insert_rule(rule)
        rules.append(rule)

        rule = iptc.Rule6()
        rule.protocol = "udp"
        rule.src = "::1"
        target = iptc.Target(rule, "REJECT")
        target.reject_with = "addr-unreach"
        rule.target = target
        self.chain.insert_rule(rule)
        rules.append(rule)

        rule = iptc.Rule6()
        rule.protocol = "tcp"
        rule.dst = "2001::/16"
        target = iptc.Target(rule, "RETURN")
        rule.target = target
        self.chain.insert_rule(rule)
        rules.append(rule)

        crules = self.chain.rules
        self.failUnless(len(rules) == len(crules))
        for rule in rules:
            self.failUnless(rule in crules)
            crules.remove(rule)


class TestRule(unittest.TestCase):
    def setUp(self):
        self.table = iptc.Table(iptc.Table.FILTER)
        self.chain = iptc.Chain(self.table, "iptc_test_chain")
        try:
            self.table.create_chain(self.chain)
        except:
            self.chain.flush()
        if is_table_available(iptc.Table.NAT):
            self.table_nat = iptc.Table(iptc.Table.NAT)
            self.chain_nat = iptc.Chain(self.table_nat, "iptc_test_nat_chain")
            try:
                self.table_nat.create_chain(self.chain_nat)
            except:
                self.chain_nat.flush()

    def tearDown(self):
        self.table.autocommit = True
        self.chain.flush()
        self.chain.delete()
        if is_table_available(iptc.Table.NAT):
            self.table_nat.autocommit = True
            self.chain_nat.flush()
            self.chain_nat.delete()

    def test_rule_address(self):
        # valid addresses
        rule = iptc.Rule()
        for addr in [("127.0.0.1/255.255.255.0", "127.0.0.1/255.255.255.0"),
                     ("!127.0.0.1/255.255.255.0", "!127.0.0.1/255.255.255.0"),
                     ("127.0.0.1/255.255.128.0", "127.0.0.1/255.255.128.0"),
                     ("127.0.0.1/16", "127.0.0.1/255.255.0.0"),
                     ("127.0.0.1/24", "127.0.0.1/255.255.255.0"),
                     ("127.0.0.1/17", "127.0.0.1/255.255.128.0"),
                     ("!127.0.0.1/17", "!127.0.0.1/255.255.128.0")]:
            rule.src = addr[0]
            self.assertEquals(rule.src, addr[1])
            rule.dst = addr[0]
            self.assertEquals(rule.dst, addr[1])
        addr = "127.0.0.1"
        rule.src = addr
        self.assertEquals("127.0.0.1/255.255.255.255", rule.src)
        rule.dst = addr
        self.assertEquals("127.0.0.1/255.255.255.255", rule.dst)

        # invalid addresses
        for addr in ["127.256.0.1/255.255.255.0", "127.0.1/255.255.255.0",
                     "127.0.0.1/255.255.255.", "127.0.0.1 255.255.255.0",
                     "127.0.0.1/33", "127.0.0.1/-5", "127.0.0.1/255.5"]:
            try:
                rule.src = addr
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid address %s" % (addr))
            try:
                rule.dst = addr
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid address %s" % (addr))

    def test_rule_interface(self):
        # valid interfaces
        rule = iptc.Rule()
        for intf in ["eth0", "eth+", "ip6tnl1", "ip6tnl+", "!ppp0", "!ppp+"]:
            rule.in_interface = intf
            self.assertEquals(intf, rule.in_interface)
            rule.out_interface = intf
            self.assertEquals(intf, rule.out_interface)
            rule.create_target("ACCEPT")
            self.chain.insert_rule(rule)
            r = self.chain.rules[0]
            eq = r == rule
            self.chain.flush()
            self.assertTrue(eq)

        # invalid interfaces
        for intf in ["itsaverylonginterfacename"]:
            try:
                rule.out_interface = intf
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid interface name %s" % (intf))
            try:
                rule.in_interface = intf
            except ValueError:
                pass
            else:
                self.fail("rule accepted invalid interface name %s" % (intf))

    def test_rule_fragment(self):
        rule = iptc.Rule()
        for frag in [("1", True), ("true", True), ("asdf", True), (1, True),
                     (0, False), ("", False), (None, False)]:
            rule.fragment = frag[0]
            self.assertEquals(frag[1], rule.fragment)

    def test_rule_protocol(self):
        rule = iptc.Rule()
        for proto in ["tcp", "udp", "icmp", "AH", "ESP", "!TCP", "!UDP",
                      "!ICMP", "!ah", "!esp"]:
            rule.protocol = proto
            self.assertEquals(proto.lower(), rule.protocol)
        for proto in ["", "asdf", "!"]:
            try:
                rule.protocol = proto
            except ValueError:
                pass
            except IndexError:
                pass
            else:
                self.fail("rule accepted invalid protocol %s" % (proto))

    def test_rule_protocol_numeric(self):
        rule = iptc.Rule()
        rule.protocol = 132
        self.assertEquals(rule.protocol, '132')
        rule.protocol = '!132'
        self.assertEquals(rule.protocol, '!132')

    def test_rule_compare(self):
        r1 = iptc.Rule()
        r1.src = "127.0.0.2/255.255.255.0"
        r1.dst = "224.1.2.3/255.255.0.0"
        r1.protocol = "tcp"
        r1.fragment = False
        r1.in_interface = "wlan+"
        r1.out_interface = "eth1"

        r2 = iptc.Rule()
        r2.src = "127.0.0.2/255.255.255.0"
        r2.dst = "224.1.2.3/255.255.0.0"
        r2.protocol = "tcp"
        r2.fragment = False
        r2.in_interface = "wlan+"
        r2.out_interface = "eth1"

        self.failUnless(r1 == r2)

        r1.src = "127.0.0.1"
        self.failIf(r1 == r2)

    def test_rule_standard_target(self):
        try:
            target = iptc.Target(iptc.Rule(), "jump_to_chain")
        except:
            pass
        else:
            self.fail("target accepted invalid name jump_to_chain")

        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.src = "127.0.0.1"

        target = iptc.Target(rule, "RETURN")
        self.assertEquals(target.name, "RETURN")
        target = iptc.Target(rule, "ACCEPT")
        self.assertEquals(target.name, "ACCEPT")
        target = iptc.Target(rule, "")
        self.assertEquals(target.name, "")
        target.standard_target = "ACCEPT"
        self.assertEquals(target.name, "ACCEPT")
        self.assertEquals(target.standard_target, "ACCEPT")

        target = iptc.Target(rule, self.chain.name)
        rule.target = target

        self.chain.insert_rule(rule)
        self.chain.delete_rule(rule)

    def test_rule_iterate_filter(self):
        if is_table_available(iptc.Table.FILTER):
            for r in (rule for chain in iptc.Table(iptc.Table.FILTER).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_iterate_nat(self):
        if is_table_available(iptc.Table.NAT):
            for r in (rule for chain in iptc.Table(iptc.Table.NAT).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_iterate_mangle(self):
        if is_table_available(iptc.Table.MANGLE):
            for r in (rule for chain in iptc.Table(iptc.Table.MANGLE).chains
                      for rule in chain.rules if rule):
                pass

    def test_rule_iterate_rulenum(self):
        """Ensure rule numbers are always returned in order"""
        insert_rule_count = 3
        append_rule_count = 3
        for rule_num in range(insert_rule_count, 0, -1):
            rule = iptc.Rule()
            match = rule.create_match("comment")
            match.comment = "rule{rule_num}".format(rule_num=rule_num)
            rule.create_target("ACCEPT")
            self.chain.insert_rule(rule)

        append_rulenum_start = insert_rule_count + 1
        append_rulenum_end = append_rulenum_start + 3
        for rule_num in range(append_rulenum_start, append_rulenum_end):
            rule = iptc.Rule()
            match = rule.create_match("comment")
            match.comment = "rule{rule_num}".format(rule_num=rule_num)
            rule.create_target("ACCEPT")
            self.chain.append_rule(rule)

        rules = self.chain.rules
        assert len(rules) == (insert_rule_count + append_rule_count)
        for rule_num, rule in enumerate(rules, start=1):
            assert len(rule.matches) == 1
            assert rule.matches[0].comment == "rule{rule_num}".format(
                rule_num=rule_num), \
                "rule[{left_num}] is not new {right_num}".format(
                    left_num=rule_num,
                    right_num=rule.matches[0].comment
                )

    def test_rule_insert(self):
        rules = []

        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.src = "127.0.0.1"
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        self.chain.insert_rule(rule)
        rules.append(rule)

        rule = iptc.Rule()
        rule.protocol = "udp"
        rule.src = "127.0.0.1"
        target = iptc.Target(rule, "REJECT")
        target.reject_with = "host-unreach"
        rule.target = target
        self.chain.insert_rule(rule)
        rules.append(rule)

        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.dst = "10.1.1.0/255.255.255.0"
        target = iptc.Target(rule, "RETURN")
        rule.target = target
        self.chain.insert_rule(rule)
        rules.append(rule)

        crules = self.chain.rules
        self.failUnless(len(rules) == len(crules))
        for rule in rules:
            self.failUnless(rule in crules)
            crules.remove(rule)

    def test_rule_replace(self):
        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.src = "127.0.0.1"
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        self.chain.insert_rule(rule, 0)

        rule = iptc.Rule()
        rule.protocol = "udp"
        rule.src = "127.0.0.1"
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target

        self.chain.replace_rule(rule, 0)
        self.failUnless(self.chain.rules[0] == rule)

    def test_rule_multiple_parameters(self):
        self.table.autocommit = False
        self.table.refresh()
        rule = iptc.Rule()
        rule.dst = "127.0.0.1"
        rule.protocol = "tcp"
        match = rule.create_match('tcp')
        match.sport = "1234"
        match.dport = "8080"
        target = rule.create_target("REJECT")
        target.reject_with = "icmp-host-unreachable"
        self.chain.insert_rule(rule)
        self.table.commit()
        self.table.refresh()
        self.assertEquals(len(self.chain.rules), 1)
        r = self.chain.rules[0]
        self.assertEquals(r.src, '0.0.0.0/0.0.0.0')
        self.assertEquals(r.dst, '127.0.0.1/255.255.255.255')
        self.assertEquals(r.protocol, 'tcp')
        self.assertEquals(len(r.matches), 1)
        m = r.matches[0]
        self.assertEquals(m.name, 'tcp')
        self.assertEquals(m.sport, '1234')
        self.assertEquals(m.dport, '8080')

    def test_rule_delete(self):
        self.table.autocommit = False
        self.table.refresh()
        for p in ['8001', '8002', '8003']:
            rule = iptc.Rule()
            rule.dst = "127.0.0.1"
            rule.protocol = "tcp"
            rule.dport = "8080"
            target = rule.create_target("REJECT")
            target.reject_with = "icmp-host-unreachable"
            self.chain.insert_rule(rule)
        self.table.commit()
        self.table.refresh()

        rules = self.chain.rules
        for rule in rules:
            self.chain.delete_rule(rule)
        self.table.commit()
        self.table.refresh()

    def test_rule_delete_nat(self):
        if not is_table_available(iptc.Table.NAT):
            return

        self.table_nat.autocommit = False
        self.table_nat.refresh()
        for p in ['8001', '8002', '8003']:
            rule = iptc.Rule()
            rule.dst = "127.0.0.1"
            rule.protocol = "udp"
            rule.dport = "8080"
            target = rule.create_target("DNAT")
            target.to_destination = '127.0.0.0:' + p
            self.chain_nat.insert_rule(rule)
        self.table_nat.commit()
        self.table_nat.refresh()

        rules = self.chain_nat.rules
        for rule in rules:
            self.chain_nat.delete_rule(rule)
        self.table_nat.commit()
        self.table_nat.refresh()


def suite():
    suite_table6 = unittest.TestLoader().loadTestsFromTestCase(TestTable6)
    suite_table = unittest.TestLoader().loadTestsFromTestCase(TestTable)
    suite_chain = unittest.TestLoader().loadTestsFromTestCase(TestChain)
    suite_rule6 = unittest.TestLoader().loadTestsFromTestCase(TestRule6)
    suite_rule = unittest.TestLoader().loadTestsFromTestCase(TestRule)
    return unittest.TestSuite([suite_table6, suite_table, suite_chain,
                               suite_rule6, suite_rule])


def run_tests():
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    if result.errors or result.failures:
        return 1
    return 0

if __name__ == "__main__":
    unittest.main()
