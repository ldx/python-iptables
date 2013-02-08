# -*- coding: utf-8 -*-

import unittest
import iptc

class TestTable6(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_table6(self):
        filt = iptc.Table6("filter")
        self.assertEquals(id(filt), id(iptc.TABLE6_FILTER))
        security = iptc.Table6("security")
        self.assertEquals(id(security), id(iptc.TABLE6_SECURITY))
        mangle = iptc.Table6("mangle")
        self.assertEquals(id(mangle), id(iptc.TABLE6_MANGLE))
        raw = iptc.Table6("raw")
        self.assertEquals(id(raw), id(iptc.TABLE6_RAW))
        self.assertNotEquals(id(filt), id(security))
        self.assertNotEquals(id(filt), id(mangle))
        self.assertNotEquals(id(security), id(mangle))
        self.assertNotEquals(id(security), id(raw))

class TestTable(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_table(self):
        filt = iptc.Table("filter")
        self.assertEquals(id(filt), id(iptc.TABLE_FILTER))
        nat = iptc.Table("nat")
        self.assertEquals(id(nat), id(iptc.TABLE_NAT))
        mangle = iptc.Table("mangle")
        self.assertEquals(id(mangle), id(iptc.TABLE_MANGLE))
        raw = iptc.Table("raw")
        self.assertEquals(id(raw), id(iptc.TABLE_RAW))
        self.assertNotEquals(id(filt), id(nat))
        self.assertNotEquals(id(filt), id(mangle))
        self.assertNotEquals(id(nat), id(mangle))
        self.assertNotEquals(id(nat), id(raw))

    def test_refresh(self):
        chain = iptc.Chain(iptc.TABLE_FILTER, "tmp_chain_for_testing")
        iptc.TABLE_FILTER.create_chain(chain)
        rule = iptc.Rule()
        match = iptc.Match(rule, "tcp")
        match.dport = "1234"
        rule.add_match(match)
        try:
            chain.insert_rule(rule)
            iptc.TABLE_FILTER.delete_chain(chain)
            self.fail("inserted invalid rule")
        except:
            pass
        iptc.TABLE_FILTER.refresh()
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        rule.protocol = "tcp"
        chain.insert_rule(rule)
        chain.delete_rule(rule)
        iptc.TABLE_FILTER.delete_chain(chain)

class TestChain(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_chain(self):
        table = iptc.TABLE_FILTER
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
        table = iptc.TABLE_FILTER
        self.assertTrue(table.is_chain("INPUT"))
        self.assertTrue(table.is_chain("FORWARD"))
        self.assertTrue(table.is_chain("OUTPUT"))

        table = iptc.TABLE_NAT
        self.assertTrue(table.is_chain("PREROUTING"))
        self.assertTrue(table.is_chain("POSTROUTING"))
        self.assertTrue(table.is_chain("OUTPUT"))

        table = iptc.TABLE_MANGLE
        self.assertTrue(table.is_chain("INPUT"))
        self.assertTrue(table.is_chain("PREROUTING"))
        self.assertTrue(table.is_chain("FORWARD"))
        self.assertTrue(table.is_chain("POSTROUTING"))
        self.assertTrue(table.is_chain("OUTPUT"))

        table = iptc.TABLE_RAW
        self.assertTrue(table.is_chain("PREROUTING"))
        self.assertTrue(table.is_chain("OUTPUT"))

    def test_builtin_chain(self):
        table = iptc.TABLE_FILTER
        self.assertTrue(table.builtin_chain("INPUT"))
        self.assertTrue(table.builtin_chain("FORWARD"))
        self.assertTrue(table.builtin_chain("OUTPUT"))

        table = iptc.TABLE_NAT
        self.assertTrue(table.builtin_chain("PREROUTING"))
        self.assertTrue(table.builtin_chain("POSTROUTING"))
        self.assertTrue(table.builtin_chain("OUTPUT"))

        table = iptc.TABLE_MANGLE
        self.assertTrue(table.builtin_chain("INPUT"))
        self.assertTrue(table.builtin_chain("PREROUTING"))
        self.assertTrue(table.builtin_chain("FORWARD"))
        self.assertTrue(table.builtin_chain("POSTROUTING"))
        self.assertTrue(table.builtin_chain("OUTPUT"))

        table = iptc.TABLE_RAW
        self.assertTrue(table.builtin_chain("PREROUTING"))
        self.assertTrue(table.builtin_chain("OUTPUT"))

    def test_chains(self):
        table = iptc.TABLE_FILTER
        table.autocommit = True
        self.assertTrue(len(table.chains) >= 3)
        for chain in table.chains:
            if chain.name not in ["INPUT", "FORWARD", "OUTPUT"]:
                self.failIf(chain.is_builtin())

        table = iptc.TABLE_NAT
        table.autocommit = True
        self.assertTrue(len(table.chains) >= 3)
        for chain in table.chains:
            if chain.name not in ["INPUT", "PREROUTING", "POSTROUTING", "OUTPUT"]:
                self.failIf(chain.is_builtin())

        table = iptc.TABLE_MANGLE
        table.autocommit = True
        self.assertTrue(len(table.chains) >= 5)
        for chain in table.chains:
            if chain.name not in ["PREROUTING", "POSTROUTING", "INPUT",
                  "FORWARD", "OUTPUT"]:
                self.failIf(chain.is_builtin())

        table = iptc.TABLE_RAW
        table.autocommit = True
        self.assertTrue(len(table.chains) >= 2)
        for chain in table.chains:
            if chain.name not in ["PREROUTING", "OUTPUT"]:
                self.failIf(chain.is_builtin())

    def test_chain_counters(self):
        for chain in (chain for table in [iptc.TABLE_FILTER, iptc.TABLE_NAT,
                iptc.TABLE_MANGLE, iptc.TABLE_RAW] for chain in table.chains):
            counters = chain.get_counters()
            chain.zero_counters()
            counters = chain.get_counters()
            if counters:   # only built-in chains
                self.failUnless(counters[0] == 0)
                self.failUnless(counters[1] == 0)

    def test_create_chain(self):
        chain = iptc.Chain(iptc.TABLE_FILTER, "tmp_chain_for_testing")
        iptc.TABLE_FILTER.create_chain(chain)
        self.failUnless(iptc.TABLE_FILTER.is_chain(chain))
        iptc.TABLE_FILTER.delete_chain(chain)
        self.failIf(iptc.TABLE_FILTER.is_chain(chain))

    def test_chain_policy(self):
        table = iptc.TABLE_FILTER
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
            fail("managed to set INPUT policy to RETURN")

        table = iptc.TABLE_NAT
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
            fail("managed to set PREROUTING policy to RETURN")

        table = iptc.TABLE_MANGLE
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
            fail("managed to set FORWARD policy to RETURN")

class TestRule6(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_rule_address(self):
        # valid addresses
        rule = iptc.Rule6()
        for addr in ["::/128",
                "!2000::1/16", "2001::/64", "!2001::1/48"]:
            rule.src = addr
            self.assertEquals(rule.src, addr)
            rule.dst = addr
            self.assertEquals(rule.dst, addr)
        addr = "::1"
        rule.src = addr
        self.assertEquals("::1/128",
                rule.src)
        rule.dst = addr
        self.assertEquals("::1/128",
                rule.dst)

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

        chain = iptc.Chain(iptc.TABLE6_FILTER, "iptc_test_chain")
        iptc.TABLE6_FILTER.create_chain(chain)
        target = iptc.Target(rule, "iptc_test_chain")
        rule.target = target

        chain.insert_rule(rule)
        chain.delete_rule(rule)

        chain.delete()

    def test_rule_iterate(self):
        for r in (rule for chain in iptc.TABLE6_FILTER.chains
              for rule in chain.rules if rule):
            pass
        for r in (rule for chain in iptc.TABLE6_RAW.chains
              for rule in chain.rules if rule):
            pass
        for r in (rule for chain in iptc.TABLE_MANGLE.chains
              for rule in chain.rules if rule):
            pass
        for r in (rule for chain in iptc.TABLE6_SECURITY.chains
              for rule in chain.rules if rule):
            pass

class TestRule(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_rule_address(self):
        # valid addresses
        rule = iptc.Rule()
        for addr in ["127.0.0.1/255.255.255.0", "!127.0.0.1/255.255.255.0"]:
            rule.src = addr
            self.assertEquals(rule.src, addr)
            rule.dst = addr
            self.assertEquals(rule.dst, addr)
        addr = "127.0.0.1"
        rule.src = addr
        self.assertEquals("127.0.0.1/255.255.255.255", rule.src)
        rule.dst = addr
        self.assertEquals("127.0.0.1/255.255.255.255", rule.dst)

        # invalid addresses
        for addr in ["127.256.0.1/255.255.255.0", "127.0.1/255.255.255.0",
                "127.0.0.1/255.255.255.", "127.0.0.1 255.255.255.0"]:
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

        chain = iptc.Chain(iptc.TABLE_FILTER, "iptc_test_chain")
        iptc.TABLE_FILTER.create_chain(chain)
        target = iptc.Target(rule, "iptc_test_chain")
        rule.target = target

        chain.insert_rule(rule)
        chain.delete_rule(rule)

        chain.delete()

    def test_rule_iterate(self):
        for r in (rule for chain in iptc.TABLE_FILTER.chains
              for rule in chain.rules if rule):
            pass
        for r in (rule for chain in iptc.TABLE_NAT.chains
              for rule in chain.rules if rule):
            pass
        for r in (rule for chain in iptc.TABLE_MANGLE.chains
              for rule in chain.rules if rule):
            pass

def suite():
    suite_table6 = unittest.TestLoader().loadTestsFromTestCase(TestTable6)
    suite_table = unittest.TestLoader().loadTestsFromTestCase(TestTable)
    suite_chain = unittest.TestLoader().loadTestsFromTestCase(TestChain)
    suite_rule6 = unittest.TestLoader().loadTestsFromTestCase(TestRule6)
    suite_rule = unittest.TestLoader().loadTestsFromTestCase(TestRule)
    return unittest.TestSuite([suite_table6, suite_table, suite_chain,
        suite_rule6, suite_rule])

def run_tests():
    unittest.TextTestRunner(verbosity=2).run(suite())

if __name__ == "__main__":
    unittest.main()
