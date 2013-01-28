#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>

int kernel_version;

#define LINUX_VERSION(x,y,z)	(0x10000*(x) + 0x100*(y) + z)
void get_kernel_version(void)
{
	static struct utsname uts;
	int x = 0, y = 0, z = 0;

	if (uname(&uts) == -1) {
		fprintf(stderr, "Unable to retrieve kernel version.\n");
        return;
	}

	sscanf(uts.release, "%d.%d.%d", &x, &y, &z);
	kernel_version = LINUX_VERSION(x, y, z);
}

static jmp_buf env;

void throw_exception(int err)
{
    longjmp(env, err);
}

int wrap_parse(int (*fn)(), int i, char **argv, int inv, unsigned int *flags,
               void *p, void **mptr)
{
    int rv = -1;
    int err;

    if ((err = setjmp(env)) == 0) {
        rv = fn(i, argv, inv, flags, p, mptr);
    } else {
        errno = err;
    }

    return rv;
}

struct xt_option_call;
int wrap_x6parse(void (*fn)(), struct xt_option_call *cb)
{
    int err;

    if ((err = setjmp(env)) == 0) {
        fn(cb);
    } else {
        errno = err;
        return -err;
    }

    return 0;
}

struct ipt_ip;
void wrap_save(int (*fn)(), const void *ip, const void *m)
{
    fn(ip, m);
    fflush(stdout);
}
