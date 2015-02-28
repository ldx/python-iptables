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

``Python-iptables`` provides a pythonesque wrapper via python bindings to
iptables under Linux.  Interoperability with iptables is achieved via using
the iptables C libraries (``libiptc``, ``libxtables``, and the iptables
extensions), not calling the iptables binary and parsing its output. It is
meant primarily for dynamic and/or complex routers and firewalls, where rules
are often updated or changed, or Python programs wish to interface with the
Linux iptables framework..

If you are looking for ``ebtables`` python bindings, check out
`python-ebtables <https://github.com/ldx/python-ebtables/>`_.

``Python-iptables`` supports Python 2.6, 2.7 and 3.4.

.. image:: http://api.flattr.com/button/flattr-badge-large.png
   :target: https://flattr.com/submit/auto?user_id=ldx&url=https%3A%2F%2Fgithub.com%2Fldx%2Fpython-iptables
   :alt: Flattr

.. image:: https://pypip.in/v/python-iptables/badge.png
   :target: https://pypi.python.org/pypi/python-iptables
   :alt: Latest Release

.. image:: https://travis-ci.org/ldx/python-iptables.png?branch=master
   :target: https://travis-ci.org/ldx/python-iptables
   :alt: Build Status

.. image:: https://pypip.in/d/python-iptables/badge.png
   :target: https://pypi.python.org/pypi/python-iptables
   :alt: Number of Downloads

.. image:: https://pypip.in/license/python-iptables/badge.png
   :target: https://pypi.python.org/pypi/python-iptables
   :alt: License

Installing via pip
------------------

The usual way::

    pip install --upgrade python-iptables

Compiling from source
----------------------

First make sure you have iptables installed (most Linux distributions install
it by default). ``Python-iptables`` needs the shared libraries ``libiptc.so``
and ``libxtables.so`` coming with iptables, they are installed in ``/lib`` on
Ubuntu.

You can compile ``python-iptables`` in the usual distutils way::

    % cd python-iptables
    % python setup.py build

If you like, ``python-iptables`` can also be installed into a ``virtualenv``::

    % mkvirtualenv python-iptables
    % python setup.py install

If you install ``python-iptables`` as a system package, make sure the
directory where ``distutils`` installs shared libraries is in the dynamic
linker's search path (it's in ``/etc/ld.so.conf`` or in one of the files in
the folder ``/etc/ld.co.conf.d``).  Under Ubuntu ``distutils`` by default
installs into ``/usr/local/lib``.

Now you can run the tests::

    % sudo PATH=$PATH ./test.py
    WARNING: this test will manipulate iptables rules.
    Don't do this on a production machine.
    Would you like to continue? y/n y
    [...]

The ``PATH=$PATH`` part is necessary after ``sudo`` if you have installed into
a ``virtualenv``, since ``sudo`` will reset your environment to a system
setting otherwise..

Once everything is in place you can fire up python to check whether the
package can be imported::

    % sudo PATH=$PATH python
    >>> import iptc
    >>>

Of course you need to be root to be able to use iptables.

Using a custom iptables install
-------------------------------

If you are stuck on a system with an old version of ``iptables``, you can
install a more up to date version to a custom location, and ask
``python-iptables`` to use libraries at that location.

To install ``iptables`` to ``/tmp/iptables``::

    % git clone git://git.netfilter.org/iptables && cd iptables
    % ./autogen.sh
    % ./configure --prefix=/tmp/iptables
    % make
    % make install

Make sure the dependencies ``iptables`` needs are installed.

Now you can point ``python-iptables`` to this install path via::

    % sudo PATH=$PATH IPTABLES_LIBDIR=/tmp/iptables/lib XTABLES_LIBDIR=/tmp/iptables/lib/xtables python
    >>> import iptc
    >>>

What is supported
-----------------

The basic iptables framework and all the match/target extensions are supported
by ``python-iptables``, including IPv4 and IPv6 ones. All IPv4 and IPv6 tables
are supported as well.

Full documentation with API reference is available here_.

.. _here: http://ldx.github.com/python-iptables/
