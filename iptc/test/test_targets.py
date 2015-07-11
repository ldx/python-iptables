# -*- coding: utf-8 -*-

import unittest
import iptc
from iptc.xtables import xtables_version


is_table_available = iptc.is_table_available


class TestTarget(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_target_create(self):
        rule = iptc.Rule()
        target = rule.create_target("MARK")

        self.failUnless(rule.target == target)

        target.set_mark = "0x123"

        t = iptc.Target(iptc.Rule(), "MARK")
        t.set_mark = "0x123"

        self.failUnless(t == target)

    def test_target_compare(self):
        t1 = iptc.Target(iptc.Rule(), "MARK")
        t1.set_mark = "0x123"

        t2 = iptc.Target(iptc.Rule(), "MARK")
        t2.set_mark = "0x123"

        self.failUnless(t1 == t2)

        t2.reset()
        t2.set_mark = "0x124"
        self.failIf(t1 == t2)

    def test_target_parameters(self):
        t = iptc.Target(iptc.Rule(), "CONNMARK")
        t.nfmask = "0xdeadbeef"
        t.ctmask = "0xfefefefe"
        t.save_mark = ""

        self.failUnless(len(t.parameters) == 3)

        for p in t.parameters:
            self.failUnless(p == "ctmask" or p == "nfmask" or
                            p == "save_mark")

        self.failUnless(t.parameters["save_mark"] == "")
        self.failUnless(t.parameters["nfmask"] == "0xdeadbeef")
        self.failUnless(t.parameters["ctmask"] == "0xfefefefe")

        t.reset()
        self.failUnless(len(t.parameters) == 1)


class TestXTClusteripTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.in_interface = "eth0"

        self.match = iptc.Match(self.rule, "tcp")
        self.rule.add_match(self.match)

        self.target = iptc.Target(self.rule, "CLUSTERIP")
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_clusterip")
        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_mode(self):
        for hashmode in ["sourceip", "sourceip-sourceport",
                         "sourceip-sourceport-destport"]:
            self.target.new = ""
            self.target.hashmode = hashmode
            self.assertEquals(self.target.hashmode, hashmode)
            self.target.reset()
        for hashmode in ["asdf", "1234"]:
            self.target.new = ""
            try:
                self.target.hashmode = hashmode
            except Exception:
                pass
            else:
                self.fail("CLUSTERIP accepted invalid value %s" % (hashmode))
            self.target.reset()

    def test_insert(self):
        self.target.reset()
        self.target.new = ""
        self.target.hashmode = "sourceip"
        self.target.clustermac = "01:02:03:04:05:06"
        self.target.local_node = "1"
        self.target.total_nodes = "2"
        self.rule.target = self.target

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestIPTRedirectTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.in_interface = "eth0"

        self.match = iptc.Match(self.rule, "tcp")
        self.rule.add_match(self.match)

        self.target = iptc.Target(self.rule, "REDIRECT")
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.NAT),
                                "iptc_test_redirect")
        iptc.Table(iptc.Table.NAT).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_mode(self):
        for port in ["1234", "1234-2345", "65534-65535"]:
            self.target.to_ports = port
            self.assertEquals(self.target.to_ports, port)
            self.target.reset()
        self.target.random = ""
        self.target.reset()
        for port in ["1234567", "2345-1234"]:  # ipt bug: it accepts strings
            try:
                self.target.to_ports = port
            except Exception:
                pass
            else:
                self.fail("REDIRECT accepted invalid value %s" % (port))
            self.target.reset()

    def test_insert(self):
        self.target.reset()
        self.target.to_ports = "1234-1235"
        self.rule.target = self.target

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestXTTosTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.in_interface = "eth0"

        self.match = iptc.Match(self.rule, "tcp")
        self.rule.add_match(self.match)

        self.target = iptc.Target(self.rule, "TOS")
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE), "iptc_test_tos")
        iptc.Table(iptc.Table.MANGLE).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_set_tos(self):
        for tos in ["0x12/0xff", "0x12/0x0f"]:
            self.target.set_tos = tos
            self.assertEquals(self.target.set_tos, tos)
            self.target.reset()
        for tos in [("Minimize-Delay", "0x10/0x3f"),
                    ("Maximize-Throughput", "0x08/0x3f"),
                    ("Maximize-Reliability", "0x04/0x3f"),
                    ("Minimize-Cost", "0x02/0x3f"),
                    ("Normal-Service", "0x00/0x3f")]:
            self.target.set_tos = tos[0]
            self.assertEquals(self.target.set_tos, tos[1])
            self.target.reset()

    def test_tos_mode(self):
        for tos in ["0x04"]:
            self.target.and_tos = tos
            self.assertEquals(self.target.set_tos, "0x00/0xfb")
            self.target.reset()
            self.target.or_tos = tos
            self.assertEquals(self.target.set_tos, "0x04/0x04")
            self.target.reset()
            self.target.xor_tos = tos
            self.assertEquals(self.target.set_tos, "0x04/0x00")
            self.target.reset()
        for tos in ["0x1234", "0x12/0xfff", "asdf", "Minimize-Bullshit"]:
            try:
                self.target.and_tos = tos
            except Exception:
                pass
            else:
                self.fail("TOS accepted invalid value %s" % (tos))
            self.target.reset()
            try:
                self.target.or_tos = tos
            except Exception:
                pass
            else:
                self.fail("TOS accepted invalid value %s" % (tos))
            self.target.reset()
            try:
                self.target.xor_tos = tos
            except Exception:
                pass
            else:
                self.fail("TOS accepted invalid value %s" % (tos))
            self.target.reset()

    def test_insert(self):
        self.target.reset()
        self.target.set_tos = "0x12/0xff"
        self.rule.target = self.target

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestDnatTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.in_interface = "eth0"

        self.match = iptc.Match(self.rule, "tcp")
        self.rule.add_match(self.match)

        self.target = iptc.Target(self.rule, "DNAT")
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.MANGLE),
                                "iptc_test_dnat")
        iptc.Table(iptc.Table.MANGLE).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_mode(self):
        for dst in ["1.2.3.4", "199.199.199.199-199.199.199.255",
                    "1.2.3.4:5678", "1.2.3.4:5678-5688"]:
            self.target.to_destination = dst
            self.assertEquals(self.target.to_destination, dst)
            self.target.reset()
            self.target.to_destination = dst
            self.target.random = "1"
            self.assertEquals(self.target.to_destination, dst)
            self.target.reset()
            self.target.to_destination = dst
            self.target.persistent = "1"
            self.assertEquals(self.target.to_destination, dst)
            self.target.reset()

    def test_insert(self):
        self.target.reset()
        self.target.to_destination = "1.2.3.4"
        self.rule.target = self.target

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestIPTMasqueradeTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.out_interface = "eth0"

        self.target = iptc.Target(self.rule, "MASQUERADE")
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.NAT),
                                "iptc_test_masquerade")
        iptc.Table(iptc.Table.NAT).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_mode(self):
        for port in ["1234", "1234-2345"]:
            self.target.to_ports = port
            self.assertEquals(self.target.to_ports, port)
            self.target.reset()
        self.target.random = ""
        self.target.reset()
        for port in ["123456", "1234-1233", "asdf"]:
            try:
                self.target.to_ports = port
            except Exception:
                pass
            else:
                self.fail("MASQUERADE accepted invalid value %s" % (port))
            self.target.reset()

    def test_insert(self):
        self.target.reset()
        self.target.to_ports = "1234"
        self.rule.target = self.target

        self.chain.insert_rule(self.rule)

        found = False
        for r in self.chain.rules:
            if r == self.rule:
                found = True
                break

        if not found:
            self.fail("inserted rule does not match original")


class TestXTNotrackTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.out_interface = "eth0"

        self.target = iptc.Target(self.rule, "NOTRACK")
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.RAW),
                                "iptc_test_notrack")
        try:
            self.chain.flush()
            self.chain.delete()
        except:
            pass
        iptc.Table(iptc.Table.RAW).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_notrack(self):
        self.chain.insert_rule(self.rule)
        t = self.chain.rules[0].target
        self.assertTrue(t.name in ["NOTRACK", "CT"])


class TestXTCtTarget(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.dst = "127.0.0.2"
        self.rule.protocol = "tcp"
        self.rule.out_interface = "eth0"

        self.target = iptc.Target(self.rule, "CT")
        self.target.notrack = "true"
        self.rule.target = self.target

        self.chain = iptc.Chain(iptc.Table(iptc.Table.RAW),
                                "iptc_test_ct")
        try:
            self.chain.flush()
            self.chain.delete()
        except:
            pass
        iptc.Table(iptc.Table.RAW).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_ct(self):
        self.chain.insert_rule(self.rule)
        t = self.chain.rules[0].target
        self.assertEquals(t.name, "CT")
        self.assertTrue(t.notrack is not None)


def suite():
    suites = []
    suite_target = unittest.TestLoader().loadTestsFromTestCase(TestTarget)
    suite_tos = unittest.TestLoader().loadTestsFromTestCase(TestXTTosTarget)
    suite_cluster = unittest.TestLoader().loadTestsFromTestCase(
        TestXTClusteripTarget)
    suite_redir = unittest.TestLoader().loadTestsFromTestCase(
        TestIPTRedirectTarget)
    suite_masq = unittest.TestLoader().loadTestsFromTestCase(
        TestIPTMasqueradeTarget)
    suite_dnat = unittest.TestLoader().loadTestsFromTestCase(
        TestDnatTarget)
    suite_notrack = unittest.TestLoader().loadTestsFromTestCase(
        TestXTNotrackTarget)
    suite_ct = unittest.TestLoader().loadTestsFromTestCase(TestXTCtTarget)
    suites.extend([suite_target, suite_cluster, suite_tos])
    if is_table_available(iptc.Table.NAT):
        suites.extend([suite_redir, suite_masq, suite_dnat])
    if is_table_available(iptc.Table.RAW) and xtables_version >= 10:
        suites.extend([suite_notrack, suite_ct])
    return unittest.TestSuite(suites)


def run_tests():
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    if result.errors or result.failures:
        return 1
    return 0

if __name__ == "__main__":
    unittest.main()
