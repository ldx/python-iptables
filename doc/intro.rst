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

Python-iptables provides python bindings to iptables under Linux.
Interoperability with iptables is achieved via using the iptables C libraries
(``libiptc``, ``libxtables``, and the iptables extensions), not calling the
iptables binary and parsing its output.

Compiling and installing
------------------------

First make sure you have iptables installed (most Linux distributions install
it by default).  python-iptables needs the shared libraries ``libiptc.so.0``
and ``libxtables.so.2`` coming with iptables, they are installed in ``/lib``
on Ubuntu.

You can compile python-iptables in the usual distutils way::

    % cd python-iptables
    % python setup.py build

To install it::

    % sudo python setup.py install
    % sudo ldconfig

Running *ldconfig* is necessary since python-iptables also contains a C
wrapper library.  Make sure the directory where distutils installs shared
libraries is in the dynamic linker's search path (it's in ``/etc/ld.so.conf``
or in one of the files in the folder ``/etc/ld.co.conf.d``).  Under Ubuntu
distutils by default installs into ``/usr/local/lib``.

Once everything is in place you can fire up python to check whether the
package can be imported::

    % sudo python
    >>> import iptc
    >>>

You need to be root to be able to use iptables.

What is supported
-----------------

The basic iptables framework and all the match/target extensions are supported
by python-iptables.  One thing we have not worked on yet is IPv6 support, but
in theory it should not be too hard.  This also means you can't use IPv6-only
match and target extensions either.

Contact
-------

ldx (at) nilvec.com

http://nilvec.com
