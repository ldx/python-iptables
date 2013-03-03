# -*- coding: utf-8 -*-

"""
.. module:: iptc
   :synopsis: Python bindings for libiptc.

.. moduleauthor:: Nilvec <nilvec@nilvec.com>
"""

from ip4tc import Table, Chain, Rule, Match, Target, Policy, IPTCError
from ip6tc import is_table_available, Table6, Rule6
from xtables import XTablesError

__all__ = []
