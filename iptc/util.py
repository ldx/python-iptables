import re
import ctypes
import ctypes.util
from subprocess import Popen, PIPE
from sys import version_info
try:
    from sysconfig import get_config_var
except ImportError:
    def get_config_var(name):
        if name == 'SO':
            return '.so'
        raise Exception('Not implemented')


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


def _do_find_library(name):
    p = ctypes.util.find_library(name)
    if p:
        lib = ctypes.CDLL(p, mode=ctypes.RTLD_GLOBAL)
        return lib

    # probably we have been installed in a virtualenv
    import os
    from distutils.sysconfig import get_python_lib
    try:
        lib = ctypes.CDLL(os.path.join(get_python_lib(), name),
                          mode=ctypes.RTLD_GLOBAL)
        return lib
    except:
        pass

    import sys
    for p in sys.path:
        try:
            lib = ctypes.CDLL(os.path.join(p, name), mode=ctypes.RTLD_GLOBAL)
            return lib
        except:
            pass
    return None


def _find_library(*names):
    ext = get_config_var('SO')
    if version_info > (3, ) and version_info < (3, 4):
        ext = '.cpython-%i%i' % (version_info.major, version_info.minor) + ext
    for name in names:
        for n in (name, "lib" + name, name + ext, "lib" + name + ext):
            lib = _do_find_library(n)
            if lib is not None:
                yield lib


def find_library(*names):
    for lib in _find_library(*names):
        major = 0
        m = re.search(r"\.so\.(\d+)", lib._name)
        if m:
            major = int(m.group(1))
        return lib, major
    return None, None
