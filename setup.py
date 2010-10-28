#!/usr/bin/env python

"""python-iptables setup script"""

import os
from distutils import ccompiler
from distutils.core import setup

execfile("iptc/version.py")

# libxtwrapper sources
LIBDIR="libxtwrapper"
csources = [os.path.join(LIBDIR, src)
        for src in os.listdir("libxtwrapper") if src.endswith(".c")]

# compile and link libxtwrapper as a shared library
compiler = ccompiler.new_compiler(compiler="unix")
objs = compiler.compile(csources, extra_preargs=["-fPIC"])
compiler.link_shared_lib(objs, "xtwrapper", output_dir=LIBDIR)
lib = [os.path.join(LIBDIR,
        compiler.library_filename("xtwrapper", lib_type="shared"))]

# build/install python-iptables
setup(
    name                = __pkgname__,
    version             = __version__,
    description         = "Python bindings for iptables",
    author              = "Nilvec",
    author_email        = "nilvec@nilvec.com",
    url                 = "http://nilvec.com/",
    packages            = ["iptc"],
    package_dir         = {"iptc" : "iptc"},
    data_files          = [("lib", lib)],
    classifiers         = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache License, Version 2.0",
        "Natural Language :: English",
        "Topic :: Networking",
    ],
    license    = "Apache License, Version 2.0",
)
