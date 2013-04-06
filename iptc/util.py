import re
import ctypes
import ctypes.util
from subprocess import Popen, PIPE


def _insert_ko(modprobe, modname):
    p = Popen([modprobe, modname], stderr=PIPE)
    p.wait()
    return (p.returncode, p.stderr.read(1024))


def _load_ko(modname):
    # this will return the full path for the modprobe binary
    proc = open("/proc/sys/kernel/modprobe")
    modprobe = proc.read(1024)
    if modprobe[-1] == '\n':
        modprobe = modprobe[:-1]
    return _insert_ko(modprobe, modname)


# Load a kernel module. If it is already loaded modprobe will just return 0.
def load_kernel(name, exc_if_failed=False):
    rc, err = _load_ko(name)
    if rc:
        if not err:
            err = "Failed to load the %s kernel module." % (name)
        if err[-1] == "\n":
            err = err[:-1]
        if exc_if_failed:
            raise Exception(err)


def _find_library(name):
    p = ctypes.util.find_library(name)
    if p:
        lib = ctypes.CDLL(p, mode=ctypes.RTLD_GLOBAL)
        return lib

    # probably we have been installed in a virtualenv
    import os
    from distutils.sysconfig import get_python_lib
    try:
        lib = ctypes.CDLL(os.path.join(get_python_lib(), 'lib%s.so' % (name)),
                          mode=ctypes.RTLD_GLOBAL)
        return lib
    except:
        pass

    import sys
    for p in sys.path:
        try:
            lib = ctypes.CDLL(os.path.join(p, 'lib%s.so' % (name)),
                              mode=ctypes.RTLD_GLOBAL)
            return lib
        except:
            pass
    return None


def find_library(*names):
    lib = None
    for name in names:
        lib = _find_library(name)
        if lib is not None:
            break
    if lib:
        major = 0
        m = re.match("libxtables.so.(\d+)", lib._name)
        if m:
            major = int(m.group(1))
        return lib, major
    else:
        return None, None
