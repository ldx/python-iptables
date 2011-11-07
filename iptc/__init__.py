# -*- coding: utf-8 -*-

"""
.. module:: iptc
   :synopsis: Python bindings for libiptc.

.. moduleauthor:: Nilvec <nilvec@nilvec.com>
"""

import os
import re
import ctypes as ct
import socket
import struct
import weakref
import ctypes.util

from xtables import XT_INV_PROTO, NFPROTO_IPV4, XTF_TRY_LOAD, XTablesError, xtables, xtables_globals, xt_align, xt_counters, xt_entry_target, xt_entry_match, _lib_xtwrapper

__all__ = ["Table", "Chain", "Rule", "Match", "Target", "Policy", "IPTCError",
           "POLICY_ACCEPT", "POLICY_DROP", "POLICY_QUEUE", "POLICY_RETURN",
           "TABLE_FILTER", "TABLE_NAT", "TABLE_MANGLE"]

from subprocess import Popen, PIPE

def insert_ko(modprobe, modname):
    p = Popen([modprobe, modname], stderr=PIPE)
    p.wait()
    return (p.returncode, p.stderr.read(1024))

def load_ko(modname):
    # this will return the full path for the modprobe binary
    proc = open("/proc/sys/kernel/modprobe")
    modprobe = proc.read(1024)
    if modprobe[len(modprobe) - 1] == '\n':
        modprobe = modprobe[:len(modprobe) - 1]
    return insert_ko(modprobe, modname)

# First load the kernel module.  If it is already loaded modprobe will just
# return with 0.
rc, err = load_ko("ip_tables")
if rc:
    if not err:
        err = "Failed to load the ip_tables kernel module."
    if err[len(err) - 1] == "\n":
        err = err[:len(err) - 1]
    raise Exception(err)

_IFNAMSIZ = 16

class in_addr(ct.Structure):
    """This class is a representation of the C struct in_addr."""
    _fields_ = [("s_addr", ct.c_uint32)]

class ipt_ip(ct.Structure):
    """This class is a representation of the C struct ipt_ip."""
    _fields_ = [("src", in_addr),
          ("dst", in_addr),
          ("smsk", in_addr),
          ("dmsk", in_addr),
          ("iniface", ct.c_char * _IFNAMSIZ),
          ("outiface", ct.c_char * _IFNAMSIZ),
          ("iniface_mask", ct.c_char * _IFNAMSIZ),
          ("outiface_mask", ct.c_char * _IFNAMSIZ),
          ("proto", ct.c_uint16),
          ("flags", ct.c_uint8),
          ("invflags", ct.c_uint8)]

    # flags
    IPT_F_FRAG = 0x01    # Set if rule is a fragment rule
    IPT_F_GOTO = 0x02    # Set if jump is a goto
    IPT_F_MASK = 0x03    # All possible flag bits mask

    # invflags
    IPT_INV_VIA_IN  = 0x01          # Invert the sense of IN IFACE
    IPT_INV_VIA_OUT = 0x02          # Invert the sense of OUT IFACE
    IPT_INV_TOS     = 0x04          # Invert the sense of TOS
    IPT_INV_SRCIP   = 0x08          # Invert the sense of SRC IP
    IPT_INV_DSTIP   = 0x10          # Invert the sense of DST OP
    IPT_INV_FRAG    = 0x20          # Invert the sense of FRAG
    IPT_INV_PROTO   = XT_INV_PROTO  # Invert the sense of PROTO (XT_INV_PROTO)
    IPT_INV_MASK    = 0x7F          # All possible flag bits mask

    def __init__(self):
        self.smsk = self.dmsk= 0xffffffff # default: full netmask

class ipt_entry(ct.Structure):
    """This class is a representation of the C struct ipt_entry."""
    _fields_ = [("ip", ipt_ip),
          ("nfcache", ct.c_uint),         # Mark with fields that we care about
          ("target_offset", ct.c_uint16), # Size of ipt_entry + matches
          ("next_offset", ct.c_uint16),   # Size of ipt_entry + matches + target
          ("comefrom", ct.c_uint),        # Back pointer
          ("counters", xt_counters),     # Packet and byte counters
          ("elems", ct.c_ubyte * 0)]      # The matches (if any) then the target

class ipt_entry_target(xt_entry_target):
    pass

class ipt_entry_match(xt_entry_match):
    pass

ipt_align = xt_align

try:
    _libiptc = ct.CDLL(ctypes.util.find_library("ip4tc"), use_errno = True)
except:
    _libiptc = ct.CDLL(ctypes.util.find_library("iptc"), use_errno = True)

class iptc(object):
    """This class contains all libiptc API calls."""
    iptc_init = _libiptc.iptc_init
    iptc_init.restype = ct.c_void_p
    iptc_init.argstype = [ct.c_char_p]

    iptc_free = _libiptc.iptc_free
    iptc_free.restype = None
    iptc_free.argstype = [ct.c_void_p]

    iptc_commit = _libiptc.iptc_commit
    iptc_commit.restype = ct.c_int
    iptc_commit.argstype = [ct.c_void_p]

    iptc_builtin = _libiptc.iptc_builtin
    iptc_builtin.restype = ct.c_int
    iptc_builtin.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_first_chain = _libiptc.iptc_first_chain
    iptc_first_chain.restype = ct.c_char_p
    iptc_first_chain.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_next_chain = _libiptc.iptc_next_chain
    iptc_next_chain.restype = ct.c_char_p
    iptc_next_chain.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_is_chain = _libiptc.iptc_is_chain
    iptc_is_chain.restype = ct.c_int
    iptc_is_chain.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_create_chain = _libiptc.iptc_create_chain
    iptc_create_chain.restype = ct.c_int
    iptc_create_chain.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_delete_chain = _libiptc.iptc_delete_chain
    iptc_delete_chain.restype = ct.c_int
    iptc_delete_chain.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_rename_chain = _libiptc.iptc_rename_chain
    iptc_rename_chain.restype = ct.c_int
    iptc_rename_chain.argstype = [ct.c_char_p, ct.c_char_p, ct.c_void_p]

    iptc_flush_entries = _libiptc.iptc_flush_entries
    iptc_flush_entries.restype = ct.c_int
    iptc_flush_entries.argstype = [ct.c_char_p, ct.c_void_p]

    iptc_zero_entries = _libiptc.iptc_zero_entries
    iptc_zero_entries.restype = ct.c_int
    iptc_zero_entries.argstype = [ct.c_char_p, ct.c_void_p]

    # Get the policy of a given built-in chain
    iptc_get_policy = _libiptc.iptc_get_policy
    iptc_get_policy.restype = ct.c_char_p
    iptc_get_policy.argstype = [ct.c_char_p, ct.POINTER(xt_counters),
          ct.c_void_p]

    # Set the policy of a chain
    iptc_set_policy = _libiptc.iptc_set_policy
    iptc_set_policy.restype = ct.c_int
    iptc_set_policy.argstype = [ct.c_char_p, ct.c_char_p,
          ct.POINTER(xt_counters), ct.c_void_p]

    # Get first rule in the given chain: NULL for empty chain.
    iptc_first_rule = _libiptc.iptc_first_rule
    iptc_first_rule.restype = ct.POINTER(ipt_entry)
    iptc_first_rule.argstype = [ct.c_char_p, ct.c_void_p]

    # Returns NULL when rules run out.
    iptc_next_rule = _libiptc.iptc_next_rule
    iptc_next_rule.restype = ct.POINTER(ipt_entry)
    iptc_next_rule.argstype = [ct.POINTER(ipt_entry), ct.c_void_p]

    # Returns a pointer to the target name of this entry.
    iptc_get_target = _libiptc.iptc_get_target
    iptc_get_target.restype = ct.c_char_p
    iptc_get_target.argstype = [ct.POINTER(ipt_entry), ct.c_void_p]

    # These functions return TRUE for OK or 0 and set errno.  If errno ==
    # 0, it means there was a version error (ie. upgrade libiptc).
    # Rule numbers start at 1 for the first rule.

    # Insert the entry `e' in chain `chain' into position `rulenum'.
    iptc_insert_entry = _libiptc.iptc_insert_entry
    iptc_insert_entry.restype = ct.c_int
    iptc_insert_entry.argstype = [ct.c_char_p, ct.POINTER(ipt_entry), ct.c_int,
          ct.c_void_p]

    # Atomically replace rule `rulenum' in `chain' with `e'.
    iptc_replace_entry = _libiptc.iptc_replace_entry
    iptc_replace_entry.restype = ct.c_int
    iptc_replace_entry.argstype = [ct.c_char_p, ct.POINTER(ipt_entry), ct.c_int,
          ct.c_void_p]

    # Append entry `e' to chain `chain'.  Equivalent to insert with
    #   rulenum = length of chain.
    iptc_append_entry = _libiptc.iptc_append_entry
    iptc_append_entry.restype = ct.c_int
    iptc_append_entry.argstype = [ct.c_char_p, ct.POINTER(ipt_entry),
          ct.c_void_p]

    # Delete the first rule in `chain' which matches `e', subject to
    #   matchmask (array of length == origfw)
    iptc_delete_entry = _libiptc.iptc_delete_entry
    iptc_delete_entry.restype = ct.c_int
    iptc_delete_entry.argstype = [ct.c_char_p, ct.POINTER(ipt_entry),
          ct.POINTER(ct.c_ubyte), ct.c_void_p]

    # Delete the rule in position `rulenum' in `chain'.
    iptc_delete_num_entry = _libiptc.iptc_delete_num_entry
    iptc_delete_num_entry.restype = ct.c_int
    iptc_delete_num_entry.argstype = [ct.c_char_p, ct.c_uint, ct.c_void_p]

    # Check the packet `e' on chain `chain'.  Returns the verdict, or
    #   NULL and sets errno.
    #iptc_check_packet = _libiptc.iptc_check_packet
    #iptc_check_packet.restype = ct.c_char_p
    #iptc_check_packet.argstype = [ct.c_char_p, ct.POINTER(ipt), ct.c_void_p]

    # Get the number of references to this chain
    iptc_get_references = _libiptc.iptc_get_references
    iptc_get_references.restype = ct.c_int
    iptc_get_references.argstype = [ct.c_uint, ct.c_char_p, ct.c_void_p]

    # read packet and byte counters for a specific rule
    iptc_read_counter = _libiptc.iptc_read_counter
    iptc_read_counter.restype = ct.POINTER(xt_counters)
    iptc_read_counter.argstype = [ct.c_char_p, ct.c_uint, ct.c_void_p]

    # zero packet and byte counters for a specific rule
    iptc_zero_counter = _libiptc.iptc_zero_counter
    iptc_zero_counter.restype = ct.c_int
    iptc_zero_counter.argstype = [ct.c_char_p, ct.c_uint, ct.c_void_p]

    # set packet and byte counters for a specific rule
    iptc_set_counter = _libiptc.iptc_set_counter
    iptc_set_counter.restype = ct.c_int
    iptc_set_counter.argstype = [ct.c_char_p, ct.c_uint,
          ct.POINTER(xt_counters), ct.c_void_p]

    # Translates errno numbers into more human-readable form than strerror.
    iptc_strerror = _libiptc.iptc_strerror
    iptc_strerror.restype = ct.c_char_p
    iptc_strerror.argstype = [ct.c_int]

class IPTCError(Exception):
    """This exception is raised when a low-level libiptc error occurs.

    It contains a short description about the error that occured while
    executing an iptables operation.
    """

_libc = ct.CDLL(ctypes.util.find_library("c"))
_optind = ct.c_long.in_dll(_libc, "optind")
_optarg = ct.c_char_p.in_dll(_libc, "optarg")

_wrap_parse = _lib_xtwrapper.wrap_parse
_wrap_save = _lib_xtwrapper.wrap_save

_xt = xtables(NFPROTO_IPV4)

class IPTCModule(object):
    """Superclass for Match and Target."""
    pattern = re.compile("\s*(\!)?\s*--([-a-zA-Z0-9_:/]+)\s+(\!)?\s*([a-zA-Z0-9_:/]+(-[a-zA-Z0-9_:/]+)*)*")

    def __init__(self):
        self._name = None
        self._rule = None
        self._module = None
        self._revision = None
        self._ptr = None
        self._ptrptr = None
        raise NotImplementedError()

    def parse(self, parameter, value):
        parameter = parameter.rstrip().lstrip()
        value = value.rstrip().lstrip()
        if "!" in value:
            inv = ct.c_int(1)
            value = value.replace("!", "")
        else:
            inv = ct.c_int(0)

        _optarg.value = value
        _optind.value = 2

        argv = (ct.c_char_p * 2)()
        argv[0] = parameter
        argv[1] = value

        for opt in self._module.extra_opts:
            if opt.name == parameter:
                entry = self._rule.entry and ct.pointer(self._rule.entry) or \
                        None
                rv = _wrap_parse(self._module.parse, opt.val, argv, inv,
                        ct.pointer(self._flags), entry, self._ptrptr)
                if rv != 1:
                    raise ValueError("invalid value %s" % (value))
                return
            elif not opt.name:
                break
        raise AttributeError("invalid parameter %s" % (parameter))

    def final_check(self):
        if self._module and self._module.final_check:
            self._module.final_check(self._flags)

    def save(self, name):
        if self._module and self._module.save:
            # redirect C stdout to a pipe and read back the output of m->save
            pipes = os.pipe()
            saved_out = os.dup(1)
            os.dup2(pipes[1], 1)
            _wrap_save(self._module.save, None, self._ptr)
            buf = os.read(pipes[0], 1024)
            os.dup2(saved_out, 1)
            os.close(pipes[0])
            os.close(pipes[1])
            return self._get_value(buf, name)
        else:
            return None

    def _get_value(self, buf, name):
        table = {} # variable -> (value, inverted)
        res = re.findall(IPTCModule.pattern, buf)
        for x in res:
            table[x[1]] = (x[3], x[0] or x[2])
        try:
            value, invert = table[name]
            return "%s%s" % (invert and "!" or "", value)
        except KeyError:
            return None

    def __setattr__(self, name, value):
        if not name.startswith('_') and name not in dir(self):
            self.parse(name.replace("_", "-"), value)
        else:
            object.__setattr__(self, name, value)

    def __getattr__(self, name):
        if not name.startswith('_'):
            return self.save(name.replace("_", "-"))

    def _get_name(self):
        return self._name
    name = property(_get_name)

    def _get_rule(self):
        return self._rule

    def _set_rule(self, rule):
        self._rule = rule
    rule = property(_get_rule, _set_rule)

class Match(IPTCModule):
    """Matches are extensions which can match for special header fields or
    other attributes of a packet.

    Target and match extensions in iptables have parameters.  These parameters
    are implemented as instance attributes in python.  However, to make the
    names of parameters legal attribute names they have to be converted.  The
    rule is to cut the leading double dash from the name, and replace
    dashes in parameter names with underscores so they are accepted by
    python as attribute names.  E.g. the *TOS* target has parameters
    *--set-tos*, *--and-tos*, *--or-tos* and *--xor-tos*; they become
    *target.set_tos*, *target.and_tos*, *target.or_tos* and *target.xor_tos*,
    respectively.  The value of a parameter is always a string, if a parameter
    does not take any value in the iptables extension, an empty string *""*
    should be used.

    """
    def __init__(self, rule, name=None, match=None, revision=0):
        """
        *rule* is the Rule object this match belongs to; it can be changed
        later via *set_rule()*.  *name* is the name of the iptables match
        extension (in lower case), *match* is the raw buffer of the match
        structure if the caller has it.  Either *name* or *match* must be
        provided.  *revision* is the revision number of the extension that
        should be used; different revisions use different structures in C and
        they usually only work with certain kernel versions.
        """
        if not name and not match:
            raise ValueError("can't create match based on nothing")
        if not name:
            name = match.u.user.name
        self._name = name
        self._rule = rule
        self._revision = revision

        module = _xt.find_match(name)
        if not module:
            raise XTablesError("can't find match %s" % (name))
        self._module = module[0]

        self._match_buf = (ct.c_ubyte * self.size)()
        if match:
            ct.memmove(ct.byref(self._match_buf), ct.byref(match), self.size)
            self._update_pointers()
        else:
            self.reset()

    def __eq__(self, match):
        basesz = ct.sizeof(xt_entry_match)
        if self.match.u.match_size == match.match.u.match_size and \
                self.match.u.user.name == match.match.u.user.name and \
                self.match.u.user.revision == match.match.u.user.revision and \
                self.match_buf[basesz:self.usersize] == \
                        match.match_buf[basesz:match.usersize]:
            return True
        return False

    def __ne__(self, rule):
        return not self.__eq__(rule)

    def _get_size(self):
        return self._module.size + ct.sizeof(xt_entry_match)
    size = property(_get_size)
    """This is the full size of the underlying C structure."""

    def _get_user_size(self):
        return self._module.userspacesize + ct.sizeof(xt_entry_match)
    usersize = property(_get_user_size)
    """This is the size of the part of the underlying C structure that is used
    in userspace."""

    def _update_pointers(self):
        self._ptr = ct.cast(ct.byref(self._match_buf),
                ct.POINTER(xt_entry_match))
        self._ptrptr = ct.cast(ct.pointer(self._ptr),
                ct.POINTER(ct.POINTER(xt_entry_match)))

    def reset(self):
        """Reset the match.

        Parameters are set to their default value, any
        flags are cleared."""
        ct.memset(ct.byref(self._match_buf), 0, self.size)
        self._update_pointers()
        m = self._ptr[0]
        m.u.user.name = self.name
        m.u.match_size = self.size
        m.u.user.revision = self._revision
        self._flags = ct.c_uint(0)
        if self._module.init:
            self._module.init(self._ptr)

    def _get_match(self):
        return ct.cast(ct.byref(self.match_buf), ct.POINTER(xt_entry_match))[0]
    match = property(_get_match)
    """This is the C structure used by the extension."""

    def _get_match_buf(self):
        return self._match_buf
    match_buf = property(_get_match_buf)
    """This is the buffer holding the C structure used by the extension."""

class Target(IPTCModule):
    """Targets specify what to do with a packet when a match is found while
    traversing the list of rule entries in a chain.

    Target and match extensions in iptables have parameters.  These parameters
    are implemented as instance attributes in python.  However, to make the
    names of parameters legal attribute names they have to be converted.  The
    rule is to cut the leading double dash from the name, and replace
    dashes in parameter names with underscores so they are accepted by
    python as attribute names.  E.g. the *TOS* target has parameters
    *--set-tos*, *--and-tos*, *--or-tos* and *--xor-tos*; they become
    *target.set_tos*, *target.and_tos*, *target.or_tos* and *target.xor_tos*,
    respectively.  The value of a parameter is always strings, if a parameter
    does not take any value in the iptables extension, an empty string ""
    should be used.
    """
    def __init__(self, rule, name=None, target=None, revision=0):
        """
        *rule* is the Rule object this match belongs to; it can be changed
        later via *set_rule()*.  *name* is the name of the iptables target
        extension (in upper case), *target* is the raw buffer of the target
        structure if the caller has it.  Either *name* or *target* must be
        provided.  *revision* is the revision number of the extension that
        should be used; different revisions use different structures in C and
        they usually only work with certain kernel versions.
        """
        if name == None and target == None:
            raise ValueError("can't create target based on nothing")
        if name == None:
            name = target.u.user.name
        self._name = name
        self._rule = rule
        self._revision = revision

        module = _xt.find_target(name)
        if not module:
            raise XTablesError("can't find target %s" % (name))
        self._module = module[0]

        self._target_buf = (ct.c_ubyte * self.size)()
        if target:
            ct.memmove(ct.byref(self._target_buf), ct.byref(target), self.size)
            self._update_pointers()
        else:
            self.reset()

    def __eq__(self, targ):
        basesz = ct.sizeof(xt_entry_target)
        if self.target.u.target_size != targ.target.u.target_size or \
                self.target.u.user.name != targ.target.u.user.name or \
                self.target.u.user.revision != targ.target.u.user.revision:
            return False
        if self.target.u.user.name == "" or \
                self.target.u.user.name == "standard" or \
                self.target.u.user.name == "ACCEPT" or \
                self.target.u.user.name == "DROP" or \
                self.target.u.user.name == "RETURN" or \
                self.target.u.user.name == "ERROR":
            return True
        if self.target_buf[basesz:self.usersize] == \
                targ.target_buf[basesz:targ.usersize]:
            return True
        return False

    def __ne__(self, rule):
        return not self.__eq__(rule)

    def _get_size(self):
        return self._module.size + ct.sizeof(xt_entry_target)
    size = property(_get_size)
    """This is the full size of the underlying C structure."""

    def _get_user_size(self):
        return self._module.userspacesize + ct.sizeof(xt_entry_target)
    usersize = property(_get_user_size)
    """This is the size of the part of the underlying C structure that is used
    in userspace."""

    def _get_standard_target(self):
        t = self._ptr[0]
        return t.u.user.name

    def _set_standard_target(self, name):
        t = self._ptr[0]
        t.u.user.name = name
        self._name = name
    standard_target = property(_get_standard_target, _set_standard_target)
    """This attribute is used for standard targets.  It can be set to
    *ACCEPT*, *DROP*, *RETURN* or to a name of a chain the rule should jump
    into."""

    def _update_pointers(self):
        self._ptr = ct.cast(ct.byref(self._target_buf),
                ct.POINTER(xt_entry_target))
        self._ptrptr = ct.cast(ct.pointer(self._ptr),
                ct.POINTER(ct.POINTER(xt_entry_target)))

    def reset(self):
        """Reset the match.  Parameters are set to their default value, any
        flags are cleared."""
        ct.memset(ct.byref(self._target_buf), 0, self.size)
        self._update_pointers()
        t = self._ptr[0]
        t.u.user.name = self.name
        t.u.target_size = self.size
        t.u.user.revision = self._revision
        self._flags = ct.c_uint(0)
        if self._module.init:
            self._module.init(self._ptr)

    def _get_target(self):
        return ct.cast(ct.byref(self.target_buf),
                ct.POINTER(xt_entry_target))[0]
    target = property(_get_target)
    """This is the C structure used by the extension."""

    def _get_target_buf(self):
        return self._target_buf
    target_buf = property(_get_target_buf)
    """This is the buffer holding the C structure used by the extension."""

class Policy(object):
    """
    If the end of a built-in chain is reached or a rule in a built-in chain
    with target RETURN is matched, the target specified by the chain policy
    determines the fate of the packet.
    """
    _cache = weakref.WeakValueDictionary()

    def __new__(cls, name):
        obj = Policy._cache.get(name, None)
        if not obj:
            obj = object.__new__(cls)
            Policy._cache[name] = obj
        return obj

    def __init__(self, name):
        self.name = name

POLICY_ACCEPT = Policy("ACCEPT")
"""If no matching rule has been found so far then accept the packet."""
POLICY_DROP = Policy("DROP")
"""If no matching rule has been found so far then drop the packet."""
POLICY_QUEUE = Policy("QUEUE")
"""If no matching rule has been found so far then queue the packet to
userspace."""
POLICY_RETURN = Policy("RETURN")
"""Return to calling chain."""

def _a_to_i(addr):
    return struct.unpack("I", addr)[0]

def _i_to_a(ip):
    return struct.pack("I", int(ip.s_addr))

class Rule(object):
    """Rules are entries in chains.

    Each rule has three parts:
        * An entry with protocol family attributes like source and destination
          address, transport protocol, etc.  If the packet does not match the
          attributes set here, then processing continues with the next rule or
          the chain policy is applied at the end of the chain.
        * Any number of matches.  They are optional, and make it possible to
          match for further packet attributes.
        * One target.  This determines what happens with the packet if it is
          matched.
    """
    protocols = { 0: "all",
          socket.IPPROTO_TCP: "tcp",
          socket.IPPROTO_UDP: "udp",
          socket.IPPROTO_ICMP: "icmp",
          socket.IPPROTO_ESP: "esp",
          socket.IPPROTO_AH: "ah" }

    def __init__(self, entry=None, chain=None):
        """
        *entry* is the ipt_entry buffer or None if the caller does not have
        it.  *chain* is the chain object this rule belongs to.
        """
        self._matches = []
        self._target = None
        self.chain = chain
        self.rule = entry

    def __eq__(self, rule):
        if self._target != rule._target:
            return False
        if len(self._matches) != len(rule._matches):
            return False
        if set(rule._matches) != set([x for x in rule._matches if x in
                self._matches]):
            return False
        if self.src == rule.src and self.dst == rule.dst and \
                self.protocol == rule.protocol and \
                self.fragment == rule.fragment and \
                self.in_interface == rule.in_interface and \
                self.out_interface == rule.out_interface:
            return True
        return False

    def __ne__(self, rule):
        return not self.__eq__(rule)

    def add_match(self, match):
        """Adds a match to the rule.  One can add any number of matches."""
        match.rule = self
        self._matches.append(match)

    def remove_match(self, match):
        """Removes *match* from the list of matches."""
        self._matches.remove(match)

    def _get_matches(self):
        return self._matches[:] # return a copy
    matches = property(_get_matches)
    """This is the list of matches held in this rule."""

    def _get_target(self):
        return self._target

    def _set_target(self, target):
        target.rule = self
        self._target = target
    target = property(_get_target, _set_target)
    """This is the target of the rule."""

    def get_src(self):
        src = ""
        if self.entry.ip.invflags & ipt_ip.IPT_INV_SRCIP:
            src = "".join([src, "!"])
        paddr = _i_to_a(self.entry.ip.src)
        try:
            addr = socket.inet_ntop(socket.AF_INET, paddr)
        except socket.error as e:
            raise IPTCError("error in internal state: invalid address")
        src = "".join([src, addr, "/"])
        paddr = _i_to_a(self.entry.ip.smsk)
        try:
            netmask = socket.inet_ntop(socket.AF_INET, paddr)
        except socket.error as e:
            raise IPTCError("error in internal state: invalid netmask")
        src = "".join([src, netmask])
        return src

    def set_src(self, src):
        if src[0] == "!":
            self.entry.ip.invflags |= ipt_ip.IPT_INV_SRCIP
            src = src[1:]
        else:
            self.entry.ip.invflags &= ~ipt_ip.IPT_INV_SRCIP & \
                  ipt_ip.IPT_INV_MASK

        slash = src.find("/")
        if slash == -1:
            addr = src
            netm = "255.255.255.255"
        else:
            addr = src[:slash]
            netm = src[slash + 1:]

        try:
            saddr = _a_to_i(socket.inet_pton(socket.AF_INET, addr))
        except socket.error as e:
            raise ValueError("invalid address %s" % (addr))
        ina = in_addr()
        ina.s_addr = ct.c_uint32(saddr)
        self.entry.ip.src = ina

        try:
            nmask = _a_to_i(socket.inet_pton(socket.AF_INET, netm))
        except socket.error as e:
            raise ValueError("invalid netmask %s" % (netm))
        neta = in_addr()
        neta.s_addr = ct.c_uint32(nmask)
        self.entry.ip.smsk = neta

    src = property(get_src, set_src)
    """This is the source network address with an optional network mask in
    string form."""

    def get_dst(self):
        dst = ""
        if self.entry.ip.invflags & ipt_ip.IPT_INV_DSTIP:
            dst = "".join([dst, "!"])
        paddr = _i_to_a(self.entry.ip.dst)
        try:
            addr = socket.inet_ntop(socket.AF_INET, paddr)
        except socket.error as e:
            raise IPTCError("error in internal state: invalid address")
        dst = "".join([dst, addr, "/"])
        paddr = _i_to_a(self.entry.ip.dmsk)
        try:
            netmask = socket.inet_ntop(socket.AF_INET, paddr)
        except socket.error as e:
            raise IPTCError("error in internal state: invalid netmask")
        dst = "".join([dst, netmask])
        return dst

    def set_dst(self, dst):
        if dst[0] == "!":
            self.entry.ip.invflags |= ipt_ip.IPT_INV_DSTIP
            dst = dst[1:]
        else:
            self.entry.ip.invflags &= ~ipt_ip.IPT_INV_DSTIP & \
                  ipt_ip.IPT_INV_MASK

        slash = dst.find("/")
        if slash == -1:
            addr = dst
            netm = "255.255.255.255"
        else:
            addr = dst[:slash]
            netm = dst[slash + 1:]

        try:
            daddr = _a_to_i(socket.inet_pton(socket.AF_INET, addr))
        except socket.error as e:
            raise ValueError("invalid address %s" % (addr))
        ina = in_addr()
        ina.s_addr = ct.c_uint32(daddr)
        self.entry.ip.dst = ina

        try:
            nmask = _a_to_i(socket.inet_pton(socket.AF_INET, netm))
        except socket.error as e:
            raise ValueError("invalid netmask %s" % (netm))
        neta = in_addr()
        neta.s_addr = ct.c_uint32(nmask)
        self.entry.ip.dmsk = neta

    dst = property(get_dst, set_dst)
    """This is the destination network address with an optional network mask
    in string form."""

    def get_in_interface(self):
        intf = ""
        if self.entry.ip.invflags & ipt_ip.IPT_INV_VIA_IN:
            intf = "".join(["!", intf])
        iface = bytearray(_IFNAMSIZ)
        iface[:len(self.entry.ip.iniface)] = self.entry.ip.iniface
        mask = bytearray(_IFNAMSIZ)
        mask[:len(self.entry.ip.iniface_mask)] = self.entry.ip.iniface_mask
        if mask[0] == 0:
            return None
        for i in xrange(_IFNAMSIZ):
            if mask[i] != 0:
                intf = "".join([intf, chr(iface[i])])
            else:
                if iface[i - 1] != 0:
                    intf = "".join([intf, "+"])
                else:
                    intf = intf[:-1]
                break
        return intf

    def set_in_interface(self, intf):
        if intf[0] == "!":
            self.entry.ip.invflags |= ipt_ip.IPT_INV_VIA_IN
            intf = intf[1:]
        else:
            self.entry.ip.invflags &= ~ipt_ip.IPT_INV_VIA_IN & \
                  ipt_ip.IPT_INV_MASK
        if len(intf) >= _IFNAMSIZ:
            raise ValueError("interface name %s too long" % (intf))
        masklen = len(intf) + 1
        if intf[len(intf) - 1] == "+":
            intf = intf[:-1]
            masklen -= 2

        self.entry.ip.iniface = \
              "".join([intf, '\x00' * (_IFNAMSIZ - len(intf))])
        self.entry.ip.iniface_mask = \
              "".join(['\x01' * masklen, '\x00' * (_IFNAMSIZ - masklen)])

    in_interface = property(get_in_interface, set_in_interface)
    """This is the input network interface e.g. *eth0*.  A wildcard match can
    be achieved via *+* e.g. *ppp+* matches any *ppp* interface."""

    def get_out_interface(self):
        intf = ""
        if self.entry.ip.invflags & ipt_ip.IPT_INV_VIA_OUT:
            intf = "".join(["!", intf])
        iface = bytearray(_IFNAMSIZ)
        iface[:len(self.entry.ip.outiface)] = \
              self.entry.ip.outiface
        mask = bytearray(_IFNAMSIZ)
        mask[:len(self.entry.ip.outiface_mask)] = \
              self.entry.ip.outiface_mask
        if mask[0] == 0:
            return None
        for i in xrange(_IFNAMSIZ):
            if mask[i] != 0:
                intf = "".join([intf, chr(iface[i])])
            else:
                if iface[i - 1] != 0:
                    intf = "".join([intf, "+"])
                else:
                    intf = intf[:-1]
                break
        return intf

    def set_out_interface(self, intf):
        if intf[0] == "!":
            self.entry.ip.invflags |= ipt_ip.IPT_INV_VIA_OUT
            intf = intf[1:]
        else:
            self.entry.ip.invflags &= ~ipt_ip.IPT_INV_VIA_OUT & \
                  ipt_ip.IPT_INV_MASK
        if len(intf) >= _IFNAMSIZ:
            raise ValueError("interface name %s too long" % (intf))
        masklen = len(intf) + 1
        if intf[len(intf) - 1] == "+":
            intf = intf[:-1]
            masklen -= 2

        self.entry.ip.outiface = \
              "".join([intf, '\x00' * (_IFNAMSIZ - len(intf))])
        self.entry.ip.outiface_mask = \
              "".join(['\x01' * masklen, '\x00' * (_IFNAMSIZ - masklen)])

    out_interface = property(get_out_interface, set_out_interface)
    """This is the output network interface e.g. *eth0*.  A wildcard match can
    be achieved via *+* e.g. *ppp+* matches any *ppp* interface."""

    def get_fragment(self):
        frag = bool(self.entry.ip.flags & ipt_ip.IPT_F_FRAG)
        if self.entry.ip.invflags & ipt_ip.IPT_INV_FRAG:
            frag = not frag
        return frag

    def set_fragment(self, frag):
        self.entry.ip.invflags &= ~ipt_ip.IPT_INV_FRAG & ipt_ip.IPT_INV_MASK
        self.entry.ip.flags = int(bool(frag))

    fragment = property(get_fragment, set_fragment)
    """This means that the rule refers to the second and further fragments of
    fragmented packets.  It can be *True* or *False*."""

    def get_protocol(self):
        if self.entry.ip.invflags & ipt_ip.IPT_INV_PROTO:
            proto = "!"
        else:
            proto = ""
        proto = "".join([proto, self.protocols[self.entry.ip.proto]])
        return proto

    def set_protocol(self, proto):
        if proto[0] == "!":
            self.entry.ip.invflags |= ipt_ip.IPT_INV_PROTO
            proto = proto[1:]
        else:
            self.entry.ip.invflags &= \
                  ~ipt_ip.IPT_INV_PROTO & ipt_ip.IPT_INV_MASK
        for p in self.protocols.items():
            if proto.lower() == p[1]:
                self.entry.ip.proto = p[0]
                return
        raise ValueError("invalid protocol %s" % (proto))

    protocol = property(get_protocol, set_protocol)
    """This is the transport layer protocol."""

    def _get_rule(self):
        if not self.entry or not self._target or not self._target.target:
            return None

        entrysz = ipt_align(ct.sizeof(ipt_entry));
        matchsz = 0
        for m in self._matches:
            matchsz += m.size
        targetsz = self._target.size

        self.entry.target_offset = entrysz + matchsz
        self.entry.next_offset = entrysz + matchsz + targetsz

        # allocate array of full length (entry + matches + target)
        buf = (ct.c_ubyte * (entrysz + matchsz + targetsz))()

        # copy entry to buf
        ptr = ct.cast(ct.pointer(self.entry), ct.POINTER(ct.c_ubyte))
        buf[:entrysz] = ptr[:entrysz]

        # copy matches to buf at offset of entrysz + match size
        offset = 0
        for m in self._matches:
            sz = m.size
            buf[entrysz+offset:entrysz+offset+sz] = m.match_buf[:sz]
            offset += sz

        # copy target to buf at offset of entrysz + matchsz
        ptr = ct.cast(ct.pointer(self._target.target), ct.POINTER(ct.c_ubyte))
        buf[entrysz+matchsz:entrysz+matchsz+targetsz] = ptr[:targetsz]

        return buf

    def _set_rule(self, entry):
        if not entry:
            self.entry = ipt_entry()
            return
        else:
            self.entry = ct.cast(ct.pointer(entry), ct.POINTER(ipt_entry))[0]

        if not isinstance(entry, ipt_entry):
            raise TypeError()

        entrysz = ipt_align(ct.sizeof(ipt_entry));
        matchsz = entry.target_offset - entrysz
        targetsz = entry.next_offset - entry.target_offset

        # iterate over matches to create blob
        if matchsz:
            off = 0
            while entrysz + off < entry.target_offset:
                match = ct.cast(ct.byref(entry.elems, off),
                        ct.POINTER(ipt_entry_match))[0]
                m = Match(self, match=match)
                self.add_match(m)
                off += m.size

        target = ct.cast(ct.byref(entry, entry.target_offset),
              ct.POINTER(ipt_entry_target))[0]
        self.target = Target(self, target=target)
        jump = self.chain.table.get_target(entry) # standard target is special
        if jump:
            self._target.standard_target = jump

    rule = property(_get_rule, _set_rule)
    """This is the raw rule buffer as iptables expects and returns it."""

    def _get_mask(self):
        if not self.entry:
            return None

        entrysz = ipt_align(ct.sizeof(ipt_entry));
        matchsz = self.entry.target_offset - entrysz
        targetsz = self.entry.next_offset - self.entry.target_offset

        # allocate array for mask
        mask = (ct.c_ubyte * (entrysz + matchsz + targetsz))()

        # fill it out
        pos = 0
        for i in xrange(pos, pos + entrysz):
            mask[i] = 0xff
        pos += entrysz
        for m in self._matches:
            for i in xrange(pos, pos + m.usersize):
                mask[i] = 0xff
            pos += m.size
        for i in xrange(pos, pos + self._target.usersize):
            mask[i] = 0xff

        return mask

    mask = property(_get_mask)
    """This is the raw mask buffer as iptables uses it when removing rules."""

class Chain(object):
    """Rules are contained by chains.

    *iptables* has built-in chains for every table, and users can also create
    additional chains.  Rule targets can specify to jump into another chain
    and continue processing its rules, or return to the caller chain.
    """
    _cache = weakref.WeakValueDictionary()

    def __new__(cls, table, name):
        obj = Chain._cache.get(table.name + "." + name, None)
        if not obj:
            obj = object.__new__(cls)
            Chain._cache[table.name + "." + name] = obj
        return obj

    def __init__(self, table, name):
        """*table* is the table this chain belongs to, *name* is the chain's
        name.

        If a chain already exists with *name* in *table* it is returned.
        """
        self.name = name
        self.table = table

    def delete(self):
        """Delete chain from its table."""
        self.table.delete_chain(self.name)

    def rename(self, new_name):
        """Rename chain to *new_name*."""
        self.table.rename_chain(self.name, new_name)

    def flush(self):
        """Flush all rules from the chain."""
        self.table.flush_entries(self.name)

    def get_counters(self):
        """This method returns a tuple pair of the packet and byte counters of
        the chain."""
        policy, counters = self.table.get_policy(self.name)
        return counters

    def zero_counters(self):
        """This method zeroes the packet and byte counters of the chain."""
        self.table.zero_entries(self.name)

    def set_policy(self, policy, counters=None):
        """Set the chain policy to *policy*.  If *counters* is not *None*, the
        chain counters are also adjusted."""
        if isinstance(policy, Policy):
            policy = policy.name
        self.table.set_policy(self.name, policy, counters)

    def get_policy(self):
        """Returns the policy of the chain."""
        policy, counters = self.table.get_policy(self.name)
        return policy

    def is_builtin(self):
        """Returns whether the chain is a built-in one."""
        return self.table.builtin_chain(self.name)

    def append_rule(self, rule):
        """Append *rule* to the end of the chain."""
        rbuf = rule.rule
        if not rbuf:
            raise ValueError("invalid rule")
        self.table.append_entry(self.name, rbuf)

    def insert_rule(self, rule, position=0):
        """Insert *rule* as the first entry in the chain if *position* is 0 or
        not specified, else *rule* is inserted in the given position."""
        rbuf = rule.rule
        if not rbuf:
            raise ValueError("invalid rule")
        self.table.insert_entry(self.name, rbuf, position)

    def delete_rule(self, rule):
        """Removes *rule* from the chain."""
        rbuf = rule.rule
        if not rbuf:
            raise ValueError("invalid rule")
        self.table.delete_entry(self.name, rbuf, rule.mask)

    def get_target(self, rule):
        """This method returns the target of *rule* if it is a standard
        target, or *None* if it is not."""
        rbuf = rule.rule
        if not rbuf:
            raise ValueError("invalid rule")
        return self.table.get_target(rbuf)

    def _get_rules(self):
        rules = []
        rule = self.table.first_rule(self.name)
        while rule:
            rules.append(Rule(rule, self))
            rule = self.table.next_rule(rule)
        return rules

    rules = property(_get_rules)
    """This is the list of rules currently in the chain."""

def autocommit(fn):
    def new(*args):
        obj = args[0]
        ret = fn(*args)
        if obj.autocommit:
            obj.refresh()
        return ret
    return new

class Table(object):
    """A table is the most basic building block in iptables.

    There are three fixed tables:
        * **TABLE_FILTER**, the filter table,
        * **TABLE_NAT**, the NAT table and
        * **TABLE_MANGLE**, the mangle table.

    The interface provided by *Table* is rather low-level, in fact it maps to
    *libiptc* API calls one by one, and take low-level iptables structs as
    parameters.  It is encouraged to use Chain, Rule, Match and Target to
    achieve what is wanted instead, since they hide the low-level details from
    the user.
    """
    _cache = weakref.WeakValueDictionary()

    def __new__(cls, name, autocommit = True):
        obj = Table._cache.get(name, None)
        if not obj:
            obj = object.__new__(cls)
            Table._cache[name] = obj
        else:
            obj.autocommit = autocommit
        return obj

    def __init__(self, name, autocommit = True):
        """
        *name* is the name of the table, if it already exists it is returned.
        *autocommit* specifies that any iptables operation that changes a
        rule, chain or table should be committed immediately.
        """
        self.name = name
        self.autocommit = autocommit
        self._iptc = iptc() # to keep references to functions
        self._handle = None
        self.refresh()

    def __del__(self):
        self.close()

    def close(self):
        """Close the underlying connection handle to iptables."""
        if self._handle:
            self._free()

    def commit(self):
        """Commit any pending operation."""
        rv = self._iptc.iptc_commit(self._handle)
        if rv != 1:
            raise IPTCError("can't commit: %s" % (self.strerror()))

    def _free(self):
        if self._handle == None:
            raise IPTCError("table is not initialized")
        self.commit()
        self._iptc.iptc_free(self._handle)

    def refresh(self):
        """Commit any pending operation and refresh the status of iptables."""
        if self._handle:
            self._free()

        handle = self._iptc.iptc_init(self.name)
        if not handle:
            raise IPTCError("can't initialize %s: %s" % (self.name,
                self.strerror()))
        self._handle = handle

    def is_chain(self, chain):
        """Returns *True* if *chain* exists as a chain."""
        if isinstance(chain, Chain):
            chain = chain.name
        if self._iptc.iptc_is_chain(chain, self._handle):
            return True
        else:
            return False

    def builtin_chain(self, chain):
        """Returns *True* if *chain* is a built-in chain."""
        if isinstance(chain, Chain):
            chain = chain.name
        if self._iptc.iptc_builtin(chain, self._handle):
            return True
        else:
            return False

    def strerror(self):
        """Returns any pending iptables error from the previous operation."""
        errno = ct.get_errno()
        if errno == 0:
            return "libiptc version error"
        return self._iptc.iptc_strerror(errno)

    @autocommit
    def create_chain(self, chain):
        """Create a new chain *chain*."""
        if isinstance(chain, Chain):
            chain = chain.name
        rv = self._iptc.iptc_create_chain(chain, self._handle)
        if rv != 1:
            raise IPTCError("can't create chain %s: %s" % (chain,
                self.strerror()))

    @autocommit
    def delete_chain(self, chain):
        """Delete chain *chain* from the table."""
        if isinstance(chain, Chain):
            chain = chain.name
        rv = self._iptc.iptc_delete_chain(chain, self._handle)
        if rv != 1:
            raise IPTCError("can't delete chain %s: %s" % (chain,
                self.strerror()))

    @autocommit
    def rename_chain(self, chain, new_name):
        """Rename chain *chain* to *new_name*."""
        if isinstance(chain, Chain):
            chain = chain.name
        rv = self._iptc.iptc_rename_chain(chain, new_name, self._handle)
        if rv != 1:
            raise IPTCError("can't rename chain %s: %s" % (chain,
                self.strerror()))

    @autocommit
    def flush_entries(self, chain):
        """Flush all rules from *chain*."""
        if isinstance(chain, Chain):
            chain = chain.name
        rv = self._iptc.iptc_flush_entries(chain, self._handle)
        if rv != 1:
            raise IPTCError("can't flush chain %s: %s" % (chain,
                self.strerror()))

    @autocommit
    def zero_entries(self, chain):
        """Zero the packet and byte counters of *chain*."""
        if isinstance(chain, Chain):
            chain = chain.name
        rv = self._iptc.iptc_zero_entries(chain, self._handle)
        if rv != 1:
            raise IPTCError("can't zero chain %s counters: %s" % (chain,
                self.strerror()))

    @autocommit
    def set_policy(self, chain, policy, counters = None):
        """Set the policy of *chain* to *policy*, and also update chain
        counters if *counters* is specified."""
        if isinstance(chain, Chain):
            chain = chain.name
        if isinstance(policy, Policy):
            policy = policy.name
        if counters:
            cntrs = xt_counters()
            cntrs.pcnt = counters[0]
            cntrs.bcnt = counters[1]
            cntrs = ct.pointer(cntrs)
        else:
            cntrs = None
        rv = self._iptc.iptc_set_policy(chain, policy, cntrs, self._handle)
        if rv != 1:
            raise IPTCError("can't set policy %s on chain %s: %s)" % (policy,
                chain, self.strerror()))

    @autocommit
    def get_policy(self, chain):
        """Returns the policy of *chain* as a string."""
        if isinstance(chain, Chain):
            chain = chain.name
        if not self.builtin_chain(chain):
            return None, None
        cntrs = xt_counters()
        pol = self._iptc.iptc_get_policy(chain, ct.pointer(cntrs), self._handle)
        if not pol:
            raise IPTCError("can't get policy on chain %s: %s" % (chain,
                self.strerror()))
        return Policy(pol), (cntrs.pcnt, cntrs.bcnt)

    @autocommit
    def append_entry(self, chain, entry):
        """Appends rule *entry* to *chain*."""
        rv = self._iptc.iptc_append_entry(chain, ct.cast(entry, ct.c_void_p),
              self._handle)
        if rv != 1:
            raise IPTCError("can't append entry to chain %s: %s)" % (chain,
                self.strerror()))

    @autocommit
    def insert_entry(self, chain, entry, position):
        """Inserts rule *entry* into *chain* at position *position*."""
        rv = self._iptc.iptc_insert_entry(chain, ct.cast(entry, ct.c_void_p),
              position, self._handle)
        if rv != 1:
            raise IPTCError("can't insert entry into chain %s: %s)" % (chain,
                self.strerror()))

    @autocommit
    def delete_entry(self, chain, entry, mask):
        """Removes rule *entry* with *mask* from *chain*."""
        rv = self._iptc.iptc_delete_entry(chain, ct.cast(entry, ct.c_void_p),
              mask, self._handle)
        if rv != 1:
            raise IPTCError("can't delete entry from chain %s: %s)" % (chain,
                self.strerror()))

    def first_rule(self, chain):
        """Returns the first rule in *chain* or *None* if it is empty."""
        rule = self._iptc.iptc_first_rule(chain, self._handle)
        if rule:
            return rule[0]
        else:
            return rule

    def next_rule(self, prev_rule):
        """Returns the next rule after *prev_rule*."""
        rule = self._iptc.iptc_next_rule(ct.pointer(prev_rule), self._handle)
        if rule:
            return rule[0]
        else:
            return rule

    def get_target(self, entry):
        """Returns the standard target in *entry*."""
        t = self._iptc.iptc_get_target(ct.pointer(entry), self._handle)
        # t can be NULL if standard target has a "simple" verdict e.g. ACCEPT
        return t

    def _get_chains(self):
        chains = []
        chain = self._iptc.iptc_first_chain(self._handle)
        while chain:
            chains.append(Chain(self, chain))
            chain = self._iptc.iptc_next_chain(self._handle)
        return chains

    chains = property(_get_chains)
    """List of chains in the table."""

    def flush(self):
        """Flush and delete all non-builtin chains the table."""
        for chain in self.chains:
            if not self.builtin_chain(chain):
                chain.flush()
                chain.delete()

TABLE_FILTER = Table("filter")
"""This is the constant for the filter table."""
TABLE_NAT = Table("nat")
"""This is the constant for the NAT table."""
TABLE_MANGLE = Table("mangle")
"""This is the constant for the mangle table."""
