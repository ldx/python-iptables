# -*- coding: utf-8 -*-

import unittest
import iptc


is_table6_available = iptc.is_table6_available


class TestMatch(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_match_create(self):
        rule = iptc.Rule()
        match = rule.create_match("udp")

        for m in rule.matches:
            self.assertEqual(m, match)

        # check that we can change match parameters after creation
        match.sport = "12345:55555"
        match.dport = "!33333"

        m = iptc.Match(iptc.Rule(), "udp")
        m.sport = "12345:55555"
        m.dport = "!33333"

        self.assertEqual(m, match)

    def test_match_compare(self):
        m1 = iptc.Match(iptc.Rule(), "udp")
        m1.sport = "12345:55555"
        m1.dport = "!33333"

        m2 = iptc.Match(iptc.Rule(), "udp")
        m2.sport = "12345:55555"
        m2.dport = "!33333"

        self.assertEqual(m1, m2)

        m2.reset()
        m2.sport = "12345:55555"
        m2.dport = "33333"
        self.assertNotEqual(m1, m2)

    def test_match_parameters(self):
        m = iptc.Match(iptc.Rule(), "udp")
        m.sport = "12345:55555"
        m.dport = "!33333"

        self.assertEqual(len(m.parameters), 2)

        for p in m.parameters:
            self.assertTrue(p == "sport" or p == "dport")

        self.assertEqual(m.parameters["sport"], "12345:55555")
        self.assertEqual(m.parameters["dport"], "!33333")

        m.reset()
        self.assertEqual(len(m.parameters), 0)

    def test_get_all_parameters(self):
        m = iptc.Match(iptc.Rule(), "udp")
        m.sport = "12345:55555"
        m.dport = "!33333"

        params = m.get_all_parameters()
        self.assertEqual(set(params['sport']), set(['12345:55555']))
        self.assertEqual(set(params['dport']), set(['!', '33333']))


class TestMultiportMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "udp"
        self.rule.create_target("ACCEPT")

        self.match = self.rule.create_match("multiport")

        table = iptc.Table(iptc.Table.FILTER)
        self.chain = iptc.Chain(table, "iptc_test_udp")
        try:
            self.chain.flush()
            self.chain.delete()
        except:
            pass

        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_multiport(self):
        self.match.dports = '1111,2222'
        self.chain.insert_rule(self.rule)
        rule = self.chain.rules[0]
        match = rule.matches[0]
        self.assertEqual(match.dports, '1111,2222')

    def test_unicode_multiport(self):
        self.match.dports = u'1111,2222'
        self.chain.insert_rule(self.rule)
        rule = self.chain.rules[0]
        match = rule.matches[0]
        self.assertEqual(match.dports, '1111,2222')


class TestXTUdpMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "udp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "udp")
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "iptc_test_udp")
        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_udp_port(self):
        for port in ["12345", "12345:65535", "!12345", "12345:12346",
                     "!12345:12346", "0:1234", "! 1234", "!0:12345",
                     "!1234:65535"]:
            self.match.sport = port
            self.assertEqual(self.match.sport, port.replace(" ", ""))
            self.match.dport = port
            self.assertEqual(self.match.dport, port.replace(" ", ""))
            self.match.reset()
        for port in ["-1", "asdf", "!asdf"]:
            try:
                self.match.sport = port
            except Exception:
                pass
            else:
                self.fail("udp accepted invalid source port %s" % (port))
            try:
                self.match.dport = port
            except Exception:
                pass
            else:
                self.fail("udp accepted invalid destination port %s" % (port))
            self.match.reset()

    def test_udp_insert(self):
        self.match.reset()
        self.match.dport = "12345"
        self.rule.add_match(self.match)

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestXTMarkMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "tcp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "mark")

        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_mark")
        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_mark(self):
        for mark in ["0x7b", "! 0x7b", "0x7b/0xfffefffe", "!0x7b/0xff00ff00"]:
            self.match.mark = mark
            self.assertEqual(self.match.mark, mark.replace(" ", ""))
            self.match.reset()
        for mark in ["0xffffffffff", "123/0xffffffff1", "!asdf", "1234:1233"]:
            try:
                self.match.mark = mark
            except Exception:
                pass
            else:
                self.fail("mark accepted invalid value %s" % (mark))
            self.match.reset()

    def test_mark_insert(self):
        self.match.reset()
        self.match.mark = "0x123"
        self.rule.add_match(self.match)

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestXTLimitMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "tcp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "limit")
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_limit")
        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_limit(self):
        for limit in ["1/sec", "5/min", "3/hour"]:
            self.match.limit = limit
            self.assertEqual(self.match.limit, limit)
            self.match.reset()
        for limit in ["asdf", "123/1", "!1", "!1/second"]:
            try:
                self.match.limit = limit
            except Exception:
                pass
            else:
                self.fail("limit accepted invalid value %s" % (limit))
            self.match.reset()

    def test_limit_insert(self):
        self.match.reset()
        self.match.limit = "1/min"
        self.rule.add_match(self.match)

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestIcmpv6Match(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule6()
        self.rule.protocol = "icmpv6"
        self.rule.in_interface = "eth0"

        self.target = self.rule.create_target("ACCEPT")

        self.match = self.rule.create_match("icmp6")
        self.match.icmpv6_type = "echo-request"

        self.table = iptc.Table6(iptc.Table6.FILTER)

        self.chain = iptc.Chain(self.table, "ip6tc_test_icmpv6")
        try:
            self.table.delete_chain(self.chain)
        except:
            pass
        self.table.create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_icmpv6(self):
        self.chain.insert_rule(self.rule)
        rule = self.chain.rules[0]
        self.assertEqual(self.rule, rule)


class TestCommentMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "udp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "comment")
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_comment")
        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_comment(self):
        comment = "comment test"
        self.match.reset()
        self.match.comment = comment
        self.chain.insert_rule(self.rule)
        self.assertEqual(self.match.comment, comment)


class TestIprangeMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.protocol = "tcp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "iprange")

        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_iprange")
        iptc.Table(iptc.Table.FILTER).create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_iprange(self):
        self.match.src_range = "192.168.1.100-192.168.1.200"
        self.match.dst_range = "172.22.33.106"
        self.rule.add_match(self.match)

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")

    def test_iprange_tcpdport(self):
        self.match.src_range = "192.168.1.100-192.168.1.200"
        self.match.dst_range = "172.22.33.106"
        self.rule.add_match(self.match)

        match = iptc.Match(self.rule, "tcp")
        match.dport = "22"
        self.rule.add_match(match)

        self.chain.insert_rule(self.rule)

        for r in self.chain.rules:
            if r != self.rule:
                self.fail("inserted rule does not match original")


class TestXTStateMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "tcp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "state")

        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_state")
        self.table = iptc.Table(iptc.Table.FILTER)
        try:
            self.chain.flush()
            self.chain.delete()
        except:
            pass
        self.table.create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_state(self):
        self.match.state = "RELATED,ESTABLISHED"
        self.rule.add_match(self.match)
        self.chain.insert_rule(self.rule)
        rule = self.chain.rules[0]
        m = rule.matches[0]
        self.assertEqual(m.name, "state")
        self.assertEqual(m.state, "RELATED,ESTABLISHED")
        self.assertEqual(rule.matches[0].name, self.rule.matches[0].name)
        self.assertEqual(rule, self.rule)


class TestXTConntrackMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "tcp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "conntrack")

        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_conntrack")
        self.table = iptc.Table(iptc.Table.FILTER)
        try:
            self.chain.flush()
            self.chain.delete()
        except:
            pass
        self.table.create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_state(self):
        self.match.ctstate = "NEW,RELATED"
        self.rule.add_match(self.match)
        self.chain.insert_rule(self.rule)
        rule = self.chain.rules[0]
        m = rule.matches[0]
        self.assertTrue(m.name, ["conntrack"])
        self.assertEqual(m.ctstate, "NEW,RELATED")


class TestHashlimitMatch(unittest.TestCase):
    def setUp(self):
        self.rule = iptc.Rule()
        self.rule.src = "127.0.0.1"
        self.rule.protocol = "udp"
        self.rule.target = iptc.Target(self.rule, "ACCEPT")

        self.match = iptc.Match(self.rule, "hashlimit")

        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),
                                "iptc_test_hashlimit")
        self.table = iptc.Table(iptc.Table.FILTER)
        try:
            self.chain.flush()
            self.chain.delete()
        except:
            pass
        self.table.create_chain(self.chain)

    def tearDown(self):
        for r in self.chain.rules:
            self.chain.delete_rule(r)
        self.chain.flush()
        self.chain.delete()

    def test_hashlimit(self):
        self.match.hashlimit_name = 'foo'
        self.match.hashlimit_mode = 'srcip'
        self.match.hashlimit_upto = '200/sec'
        self.match.hashlimit = '200'
        self.match.hashlimit_htable_expire = '100'
        self.rule.add_match(self.match)
        self.chain.insert_rule(self.rule)
        rule = self.chain.rules[0]
        m = rule.matches[0]
        self.assertTrue(m.name, ["hashlimit"])
        self.assertEqual(m.hashlimit_name, "foo")
        self.assertEqual(m.hashlimit_mode, "srcip")
        self.assertEqual(m.hashlimit_upto, "200/sec")
        self.assertEqual(m.hashlimit_burst, "5")


def suite():
    suite_match = unittest.TestLoader().loadTestsFromTestCase(TestMatch)
    suite_udp = unittest.TestLoader().loadTestsFromTestCase(TestXTUdpMatch)
    suite_mark = unittest.TestLoader().loadTestsFromTestCase(TestXTMarkMatch)
    suite_limit = unittest.TestLoader().loadTestsFromTestCase(TestXTLimitMatch)
    suite_mport = unittest.TestLoader().loadTestsFromTestCase(
        TestMultiportMatch)
    suite_comment = unittest.TestLoader().loadTestsFromTestCase(
        TestCommentMatch)
    suite_iprange = unittest.TestLoader().loadTestsFromTestCase(
        TestIprangeMatch)
    suite_state = unittest.TestLoader().loadTestsFromTestCase(TestXTStateMatch)
    suite_conntrack = unittest.TestLoader().loadTestsFromTestCase(
        TestXTConntrackMatch)
    suite_hashlimit = unittest.TestLoader().loadTestsFromTestCase(
        TestHashlimitMatch)
    extra_suites = []
    if is_table6_available(iptc.Table6.FILTER):
        extra_suites += unittest.TestLoader().loadTestsFromTestCase(
            TestIcmpv6Match)

    return unittest.TestSuite([suite_match, suite_udp, suite_mark,
                               suite_limit, suite_mport, suite_comment,
                               suite_iprange, suite_state, suite_conntrack,
                               suite_hashlimit] + extra_suites)


def run_tests():
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    if result.errors or result.failures:
        return 1
    return 0

if __name__ == "__main__":
    unittest.main()
