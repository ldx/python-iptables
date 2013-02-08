Usage
=====

The python API in *python-iptables* tries to mimic the logic of iptables.  You
have

    * **Tables**, **TABLE_FILTER**, **TABLE_NAT** and **TABLE_MANGLE**.  They
      can be used to filter packets, do network address translation or modify
      packets in various ways.

    * **Chains** inside tables.  Each table has a few built-in chains, but you
      can also create your own chains and jump into them from other chains.
      When you create your chains you should also specify which table it will
      be used in.

    * Each chain has zero or more **rules**.  A rule specifies what kind of
      packets to match (matches, each rule can have zero, one or more matches)
      and what to do with them (target, each rule has one of them).  Iptables
      implements a plethora of match and target extensions.

    * **Matches**, specifying when a rule needs to be applied to a packet.  To
      create a match object you also has to specify the rule to which it
      belongs.

    * **Targets**, specifying what to do when a rule is applied to a packet.
      To create a target object you also has to specify the rule to which it
      belongs.

The python API is quite high-level and hides the low-level details from the
user.  Using only the classes *Table*, *Chain*, *Rule*, *Match* and *Target*
virtually anything can be achieved that you can do with iptables from the
command line.

.. currentmodule:: iptc

Table
-----

.. autoclass:: Table
   :members:

Chain
-----

.. autoclass:: Chain
   :members:

Policy
------

.. autoclass:: Policy
   :members:

Match
-----

.. autoclass:: Match
   :members:

Target
------

.. autoclass:: Target
   :members:

Rule
----

.. autoclass:: Rule
   :members:

IPTCError
---------

.. autoexception:: IPTCError

