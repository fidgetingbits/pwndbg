"""
Commands for dealing with Linux kernel slub allocator. Only SLUB is supported.

This is a port of libslub https://github.com/nccgroup/libslub, which in turn 
was inspired from https://github.com/NeatMonster/slabdbg. This is it meant 
to eventually be a replacement of the existing slab.py functionality.
"""
from __future__ import annotations

import logging
import os
import sys

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.config
import pwndbg.gdblib.symbol
import pwndbg.gdblib.arch
import pwndbg.gdblib.kernel
from pwndbg.commands import CommandCategory

# libslub files assume libslub namespace is accessible, so add it to sys.path
module_path = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
sys.path.append(os.path.join(module_path, "..", "modules", "libslub"))

import gdb
import libslub.debugger
import libslub.commands.cache as cmd_cache
import libslub.commands.object as cmd_object
import libslub.commands.list as cmd_list
import libslub.commands.meta as cmd_meta
import libslub.commands.breaks as cmd_breaks
import libslub.commands.trace as cmd_trace
import libslub.commands.watch as cmd_watch
import libslub.commands.db as cmd_db
import libslub.commands.crosscache as cmd_crosscache
import libslub.frontend.helpers as helpers

import libslub.logger as logger
import libslub.slub.sb


# Define interface methods for libslub
class PwndbgDebugger(libslub.debugger.DebuggerInterface):
    """Implement the libslub debugger interface"""

    def is_32bit(self):
        return pwndbg.gdblib.arch.ptrsize == 4

    def is_64bit(self):
        return pwndbg.gdblib.arch.ptrsize == 8

    def is_alive(self):
        # TODO: Does its work for the kernel?
        return pwndbg.gdblib.proc.alive

    def get_arch_name(self):
        return pwndbg.gdblib.arch.name

    def get_kernel_version(self):
        return pwndbg.gdblib.kernel.kversion()

    def get_ptrsize(self):
        return pwndbg.gdblib.arch.ptrsize

    # This should possibly be in a default implementation for all gdb frameworks
    def execute(self, cmd, to_string=True):
        return gdb.execute(cmd, to_string=to_string)

    def read_memory(self, address, length):
        return pwndbg.gdblib.memory.read(address, length)

    def tohex(self, val, nbits):
        """Handle gdb adding extra char to hexadecimal values"""

        result = hex((val + (1 << nbits)) % (1 << nbits))
        # -1 because hex() only sometimes tacks on a L to hex values...
        if result[-1] == "L":
            return result[:-1]
        else:
            return result

    def parse_variable(self, variable=None):
        if variable is None:
            print(M.error("Please specify a variable to read"))
            return None
        # TODO: Not sure if pwndbg has something like tohex already, so just
        # re-implemented it above for now :/
        addr = int(pwndbg.gdblib.symbol.parse_and_eval(variable))
        return int(self.tohex(addr, self.get_ptrsize() * 8), 16)

    def parse_address(self, addresses):
        """This is simplified from the original libslub implementation, since we
        don't want to violate typical pwndbg symbol resolution (ex: turning rdi
        into $rdi)"""

        resolved = []
        if type(addresses) != list:
            addresses = [addresses]
        for item in addresses:
            addr = None
            try:
                addr = self.parse_variable(str(item))
            except Exception as e:
                print(M.error(f"ERROR: Unable to parse {item}: {e}"))
                continue
            if addr is not None:
                resolved.append(addr)
        return resolved

    def print_hexdump(self, address, size, unit=8):
        """See debugger.py interface"""
        if unit == 1:
            if type(unit) != int:
                print(M.error("ERROR: Invalid unit specified"))
                return
            result = pwndbg.hexdump.hexdump(
                pwndbg.gdblib.memory.read(address, size),
                address=address,
            )
            for i, line in enumerate(result):
                print(line)
        elif unit == "dps":
            rows = pwndbg.commands.telescope.telescope(address, count=size / self.get_ptrsize())
        else:
            # TODO: Not sure if pwndbg has something for hexdumping these sizes
            if unit == 2:
                cmd = "x/%dhx 0x%x\n" % (size / 2, address)
            elif unit == 4:
                cmd = "x/%dwx 0x%x\n" % (size / 4, address)
            elif unit == 8:
                cmd = "x/%dgx 0x%x\n" % (size / 8, address)
            print(self.execute(cmd, to_string=True))

    # TODO: The existing pwndbg search implementation isn't robust enough todo
    # this yet, as it relies on regions only, and not explicit addresses... this
    # should be fixed in a separate PR, and then this implementation can be modified
    def search(self, start_address, end_address, search_value, search_type="string"):
        """See debugger.py interface"""

        gdb_modifiers = {
            "byte": "b",
            "word": "h",
            "dword": "w",
            "qword": "g",
            "string": "b",  # see below why
        }
        # We don't use find /s because it would assume a null terminator
        # so instead we convert into bytes
        if search_type == "string":
            search_value = ", ".join("0x{:02x}".format(ord(c)) for c in search_value)
        search_type = gdb_modifiers[search_type]
        cmd = "find /1%s 0x%x, 0x%x, %s" % (
            search_type,
            start_address,
            end_address,
            search_value,
        )
        result = gdb.execute(cmd, from_tty=True, to_string=True)

        str_results = result.split("\n")
        for str_result in str_results:
            if str_result.startswith("0x"):
                return True

        return False

    def warning(self, msg):
        print(M.warning(msg))

    def error(self, msg):
        print(M.error(msg))

    def exception(self):
        pwndbg.exception.handle()

    def get_backtrace(self):
        return helpers.get_backtrace()

    def get_page_address(self, page):
        return pwndbg.gdblib.kernel.page_to_virt(page)


breakpoints_enabled = pwndbg.gdblib.config.add_param(
    "slub-breakpoints-enabled", False, "whether to use break points to enhance slub commands"
)


def init_libslub():
    # This allows changing the log level and reloading in gdb even if the logger was already defined
    try:
        log
    except Exception:
        log = logging.getLogger("libslub")
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logger.MyFormatter(datefmt="%H:%M:%S"))
        log.addHandler(handler)
    # log.setLevel(logging.TRACE) # use for debugging reloading .py files only
    # log.setLevel(logging.DEBUG)  # all other types of debugging
    log.setLevel(logging.NOTSET)

    if log.isEnabledFor(logging.TRACE):
        log.warning(f"logging TRACE enabled")
    elif log.isEnabledFor(logging.DEBUG):
        log.warning(f"logging DEBUG enabled")
    # elif log.isEnabledFor(logging.INFO):
    #     log.warning(f"logging INFO enabled")
    # elif log.isEnabledFor(logging.WARNING):
    #     log.warning(f"logging WARNING enabled")
    log.trace("pwndbg/commands/slub.py")

    di = PwndbgDebugger()
    global breakpoints_enabled
    return libslub.slub.sb.Slub(debugger=di, breakpoints_enabled=breakpoints_enabled)


sb = None


def initialize_slub(*args, **kwargs):
    global sb
    if sb == None:
        sb = init_libslub()
    return sb


@pwndbg.commands.ArgparsedCommand(
    cmd_list.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slublist(args) -> None:
    if args.help:
        cmd_list.generate_parser().print_help()
        return
    cmd_list.slub_list(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_cache.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubcache(args) -> None:
    if args.help:
        cmd_cache.generate_parser().print_help()
        return
    cmd_cache.slub_cache(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_object.generate_parser("sbobject"), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubobject(args) -> None:
    if args.help:
        cmd_object.generate_parser("sbobject").print_help()
        return
    cmd_object.slub_object(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_db.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubdb(args) -> None:
    if args.help:
        cmd_db.generate_parser().print_help()
        return
    cmd_db.slub_db(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_meta.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubmeta(args) -> None:
    if args.help:
        cmd_meta.generate_parser().print_help()
        return
    cmd_meta.slub_meta(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_crosscache.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubcrosscache(args) -> None:
    if args.help:
        cmd_crosscache.generate_parser().print_help()
        return
    cmd_crosscache.slub_crosscache(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_watch.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubwatch(args) -> None:
    if args.help:
        cmd_watch.generate_parser().print_help()
        return
    if not pwndbg.gdblib.config.slub_breakpoints_enabled:
        print(M.error("Breakpoints are disabled. Enable them with slub-breakpoints-enabled"))
        return
    cmd_watch.slub_watch(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_trace.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubtrace(args) -> None:
    if args.help:
        cmd_trace.generate_parser().print_help()
        return
    if not pwndbg.gdblib.config.slub_breakpoints_enabled:
        print(M.error("Breakpoints are disabled. Enable them with slub-breakpoints-enabled"))
        return
    cmd_trace.slub_trace(initialize_slub(), args)


@pwndbg.commands.ArgparsedCommand(
    cmd_breaks.generate_parser(), explode_args=False, category=CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slubbreak(args) -> None:
    if args.help:
        cmd_breaks.generate_parser().print_help()
        return
    if not pwndbg.gdblib.config.slub_breakpoints_enabled:
        print(M.error("Breakpoints are disabled. Enable them with slub-breakpoints-enabled"))
        return
    cmd_breaks.slub_break(initialize_slub(), args)
