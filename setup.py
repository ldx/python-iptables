#!/usr/bin/env python

"""python-iptables setup script"""

from distutils.core import setup, Extension

# make pyflakes happy
__pkgname__ = None
__version__ = None
exec(open("iptc/version.py").read())

# build/install python-iptables
setup(
    name=__pkgname__,
    version=__version__,
    description="Python bindings for iptables",
    author="Vilmos Nebehaj",
    url="https://github.com/ldx/python-iptables",
    packages=["iptc"],
    package_dir={"iptc": "iptc"},
    ext_modules=[Extension("libxtwrapper",
                           ["libxtwrapper/wrapper.c"])],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Systems Administration",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    license="Apache License, Version 2.0",
)
