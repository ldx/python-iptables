#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

static jmp_buf env;

void throw_exception(int err)
{
    longjmp(env, err);
}

int wrap_parse(int (*fn)(), int i, char **argv, int inv, unsigned int *flags,
               char *p, void **mptr)
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

struct xt_entry_match;
int wrap_save(int (*fn)(), const void *ip, const struct xt_entry_match *match)
{
    fn(ip, match);
    fflush(stdout);
}
