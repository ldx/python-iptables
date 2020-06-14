Usage
=====

The python API in ``python-iptables`` tries to mimic the logic of iptables.
You have

    * **Tables**, **Table.FILTER**, **Table.NAT**, **Table.MANGLE** and
      **Table.RAW** for IPv4; **Table6.FILTER**, **Table6.SECURITY**,
      **Table6.MANGLE** and **Table6.RAW** for IPv6.  They can be used to
      filter packets, do network address translation or modify packets in
      various ways.

    * **Chains** inside tables.  Each table has a few built-in chains, but you
      can also create your own chains and jump into them from other chains.
      When you create your chains you should also specify which table it will
      be used in. **Chains** have **Policies**, which tell what to do when the
      end of a chain is reached.

    * Each chain has zero or more **rules**.  A rule specifies what kind of
      packets to match (matches, each rule can have zero, one or more matches)
      and what to do with them (target, each rule has one of them).  Iptables
      implements a plethora of match and target extensions. For IPv4, the
      class implementing this is called *Rule*, for IPv6 it is called *Rule6*.

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

Table6
------

.. autoclass:: Table6
   :members:
   :inherited-members:

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
   :inherited-members:

Target
------

.. autoclass:: Target
   :members:
   :inherited-members:

Rule
----

.. autoclass:: Rule
   :members:
   :inherited-members:

Rule6
-----

.. autoclass:: Rule6
   :members:
   :inherited-members:

IPTCError
---------

.. autoexception:: IPTCError

