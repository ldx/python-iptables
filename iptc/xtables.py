# -*- coding: utf-8 -*-

import ctypes as ct
import ctypes.util
import version

XT_INV_PROTO   = 0x40       # Invert the sense of PROTO

NFPROTO_UNSPEC   =  0
NFPROTO_IPV4     =  2
NFPROTO_ARP      =  3
NFPROTO_BRIDGE   =  7
NFPROTO_IPV6     = 10
NFPROTO_DECNET   = 12
NFPROTO_NUMPROTO = 6

XTF_DONT_LOAD         = 0x00
XTF_DURING_LOAD       = 0x01
XTF_TRY_LOAD          = 0x02
XTF_LOAD_MUST_SUCCEED = 0x03

_WORDLEN = ct.sizeof(ct.c_long)
_XT_FUNCTION_MAXNAMELEN = 30

def xt_align(sz):
    return ((sz + (_WORDLEN - 1)) & ~(_WORDLEN - 1))

class xt_counters(ct.Structure):
    """This class is a representation of the C struct xt_counters."""
    _fields_ = [("pcnt", ct.c_uint64), # Packet counter
          ("bcnt", ct.c_uint64)]       # Byte counter

class xt_entry_target_user(ct.Structure):
    _fields_ = [("target_size", ct.c_uint16),
          ("name", ct.c_char * (_XT_FUNCTION_MAXNAMELEN - 1)),
          ("revision", ct.c_uint8)]

class xt_entry_target_u(ct.Union):
    _fields_ = [("user", xt_entry_target_user),
          ("target_size", ct.c_uint16)] # Full length

class xt_entry_target(ct.Structure):
    """This class is a representation of the C struct xt_entry_target."""
    _fields_ = [("u", xt_entry_target_u),
          ("data", ct.c_ubyte * 0)]

class xt_entry_match_user(ct.Structure):
    _fields_ = [("match_size", ct.c_uint16),
          ("name", ct.c_char * (_XT_FUNCTION_MAXNAMELEN - 1)),
          ("revision", ct.c_uint8)]

class xt_entry_match_u(ct.Union):
    _fields_ = [("user", xt_entry_match_user),
          ("match_size", ct.c_uint16)] # Full length

class xt_entry_match(ct.Structure):
    """This class is a representation of the C struct xt_entry_match."""
    _fields_ = [("u", xt_entry_match_u),
          ("data", ct.c_ubyte * 0)]

class xtables_globals(ct.Structure):
    _fields_ = [("option_offset", ct.c_uint),
            ("program_name", ct.c_char_p),
            ("program_version", ct.c_char_p),
            ("orig_opts", ct.c_void_p),
            ("opts", ct.c_void_p),
            ("exit_err", ct.CFUNCTYPE(None, ct.c_int, ct.c_char_p))]

# struct used by getopt()
class option(ct.Structure):
    _fields_ = [("name", ct.c_char_p),
            ("has_arg", ct.c_int),
            ("flag", ct.POINTER(ct.c_int)),
            ("val", ct.c_int)]

class xtables_match(ct.Structure):
    _fields_ = [("version", ct.c_char_p),
            ("next", ct.c_void_p),
            ("name", ct.c_char_p),
            ("revision", ct.c_uint8),
            ("family", ct.c_uint16),
            ("size", ct.c_size_t),
            ("userspacesize", ct.c_size_t),
            ("help", ct.CFUNCTYPE(None)),
            ("init", ct.CFUNCTYPE(None, ct.POINTER(xt_entry_match))),
            # fourth parameter entry is struct ipt_entry for example
            # int (*parse)(int c, char **argv, int invert, unsigned int *flags,
            #              const void *entry, struct xt_entry_match **match);
            ("parse", ct.CFUNCTYPE(ct.c_int, ct.c_int,
                ct.POINTER(ct.c_char_p), ct.c_int,
                ct.POINTER(ct.c_uint), ct.c_void_p,
                ct.POINTER(ct.POINTER(xt_entry_match)))),
            ("final_check", ct.CFUNCTYPE(None, ct.c_uint)),
            # Prints out the match iff non-NULL: put space at end
            # first parameter ip is struct ipt_ip * for example
            ("print", ct.CFUNCTYPE(None, ct.c_void_p,
                ct.POINTER(xt_entry_match), ct.c_int)),
            # Saves the match info in parsable form to stdout.
            # first parameter ip is struct ipt_ip * for example
            ("save", ct.CFUNCTYPE(None, ct.c_void_p,
                ct.POINTER(xt_entry_match))),
            # Pointer to list of extra command-line options
            ("extra_opts", ct.POINTER(option)),
            # Ignore these men behind the curtain:
            ("option_offset", ct.c_uint),
            ("m", ct.POINTER(xt_entry_match)),
            ("mflags", ct.c_uint),
            ("loaded", ct.c_uint)]

class xtables_target(ct.Structure):
    _fields_ = [("version", ct.c_char_p),
            ("next", ct.c_void_p),
            ("name", ct.c_char_p),
            ("revision", ct.c_uint8),
            ("family", ct.c_uint16),
            ("size", ct.c_size_t),
            ("userspacesize", ct.c_size_t),
            ("help", ct.CFUNCTYPE(None)),
            ("init", ct.CFUNCTYPE(None, ct.POINTER(xt_entry_target))),
            # fourth parameter entry is struct ipt_entry for example
            # int (*parse)(int c, char **argv, int invert, unsigned int *flags,
            #              const void *entry, struct xt_entry_target **target);
            ("parse", ct.CFUNCTYPE(ct.c_int,
                ct.POINTER(ct.c_char_p), ct.c_int,
                ct.POINTER(ct.c_uint), ct.c_void_p,
                ct.POINTER(ct.POINTER(xt_entry_target)))),
            ("final_check", ct.CFUNCTYPE(None, ct.c_uint)),
            # Prints out the target iff non-NULL: put space at end
            # first parameter ip is struct ipt_ip * for example
            ("print", ct.CFUNCTYPE(None, ct.c_void_p,
                ct.POINTER(xt_entry_target), ct.c_int)),
            # Saves the target info in parsable form to stdout.
            # first parameter ip is struct ipt_ip * for example
            ("save", ct.CFUNCTYPE(None, ct.c_void_p,
                ct.POINTER(xt_entry_target))),
            # Pointer to list of extra command-line options
            ("extra_opts", ct.POINTER(option)),
            # Ignore these men behind the curtain:
            ("option_offset", ct.c_uint),
            ("t", ct.POINTER(xt_entry_target)),
            ("tflags", ct.c_uint),
            ("used", ct.c_uint),
            ("loaded", ct.c_uint)]

class XTablesError(Exception):
    """Raised when an xtables call fails for some reason."""

_lib_xtables = ct.CDLL(ctypes.util.find_library("xtables"), mode=ct.RTLD_GLOBAL)

from distutils.sysconfig import get_python_lib
import sys
for p in sys.path:
    try:
        _lib_xtwrapper = ct.CDLL('/'.join([p, 'libxtwrapper.so']))
    except:
        pass
    else:
        break
_throw = _lib_xtwrapper.throw_exception

def xt_exit(status, *args):
    _throw(status)
EXIT_FN = ct.CFUNCTYPE(None, ct.c_int, ct.c_char_p)
xt_exit = EXIT_FN(xt_exit)

class xtables(object):
    _xtables_init_all = _lib_xtables.xtables_init_all
    _xtables_init_all.restype = ct.c_int
    _xtables_init_all.argtypes = [ct.POINTER(xtables_globals), ct.c_uint8]

    _xtables_find_match = _lib_xtables.xtables_find_match
    _xtables_find_match.restype = ct.POINTER(xtables_match)
    _xtables_find_match.argtypes = [ct.c_char_p, ct.c_int, ct.c_void_p]

    _xtables_find_target = _lib_xtables.xtables_find_target
    _xtables_find_target.restype = ct.POINTER(xtables_target)
    _xtables_find_target.argtypes = [ct.c_char_p, ct.c_int]

    def __init__(self, proto):
        self._xt_globals = xtables_globals()
        self._xt_globals.option_offset = 0
        self._xt_globals.program_name = version.__pkgname__
        self._xt_globals.program_version = version.__version__
        self._xt_globals.orig_opts = None
        self._xt_globals.opts = None
        self._xt_globals.exit_err = xt_exit
        rv = xtables._xtables_init_all(ct.pointer(self._xt_globals), proto)
        if rv:
            raise XTablesError("xtables_init_all() failed: %d" % (rv))

    def find_match(self, name):
        return xtables._xtables_find_match(name, XTF_TRY_LOAD, None)

    def find_target(self, name):
        return xtables._xtables_find_target(name, XTF_TRY_LOAD)
