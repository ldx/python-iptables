# -*- coding: utf-8 -*-

"""
.. module:: iptc
   :synopsis: Python bindings for libiptc.

.. moduleauthor:: Nilvec <nilvec@nilvec.com>
"""

from ip4tc import Table, Chain, Rule, Match, Target, Policy, IPTCError, POLICY_ACCEPT, POLICY_DROP, POLICY_QUEUE, POLICY_RETURN, TABLE_FILTER, TABLE_NAT, TABLE_MANGLE, TABLES
from xtables import XTablesError

__all__ = []
