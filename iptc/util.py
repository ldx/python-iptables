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
