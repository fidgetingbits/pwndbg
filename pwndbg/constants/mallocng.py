# http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n14
IB = 4  # in-band metadata size
UNIT = 16

UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1

# FIXME: Move these as they are more just musl specific
MAGIC_VARIABLES = [
    "__malloc_context->secret",
    "__malloc_replaced",
    "__stderr_used",
    "__stdin_used",
    "__stdout_used",
    "ofl_head",
    "__environ",
    "__stack_chk_guard",
]
MAGIC_FUNCTIONS = ["system", "execve", "fexecve", "open", "read", "write", "syscall"]
