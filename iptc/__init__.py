# -*- coding: utf-8 -*-

"""
.. module:: iptc
   :synopsis: Python bindings for libiptc.

.. moduleauthor:: Nilvec <nilvec@nilvec.com>
"""

from ip4tc import Table, Chain, Rule, Match, Target, Policy, IPTCError, \
POLICY_ACCEPT, POLICY_DROP, POLICY_QUEUE, POLICY_RETURN, TABLE_FILTER, \
TABLE_NAT, TABLE_MANGLE, TABLE_RAW, TABLES
from ip6tc import Table6, Rule6, TABLE6_FILTER, TABLE6_MANGLE, TABLE6_RAW, \
TABLE6_SECURITY, TABLES6
from xtables import XTablesError

__all__ = []
