from __future__ import annotations

import re
from pathlib import Path
from typing import Dict
from typing import List
from typing import Tuple
from typing import Any
from pwnlib.term import text

import pwndbg

from pwndbg.lib.common import hex
from pwndbg.lib.common import bin
from pwndbg.color import message
from pwndbg.constants import mallocng


class Printer:
    """A helper class for pretty printing"""

    def __init__(
        self,
        header_rjust: int | None = None,
        header_ljust: int | None = None,
        header_clr: int | None = None,
        content_clr: int | None = None,
    ) -> None:
        self.HEADER_RJUST = header_rjust
        self.HEADER_LJUST = header_ljust
        self.HEADER_CLR = header_clr
        self.CONTENT_CLR = content_clr

    def set(
        self,
        header_rjust: int | None = None,
        header_ljust: int | None = None,
        header_clr: int | None = None,
        content_clr: int | None = None,
    ) -> None:
        """Set Printer config for coloring and aligning"""

        if header_rjust:
            self.HEADER_RJUST = header_rjust
        if header_ljust:
            self.HEADER_LJUST = header_ljust
        if header_clr:
            self.HEADER_CLR = header_clr
        if content_clr:
            self.CONTENT_CLR = content_clr

    def print(self, header: str, content: str, warning: str = "") -> None:
        """Print out message with coloring and aligning"""

        header, content, warning = map(str, (header, content, warning))

        # Aligning (header)
        if self.HEADER_RJUST:
            header = header.rjust(self.HEADER_RJUST)
        elif self.HEADER_LJUST:
            header = header.ljust(self.HEADER_LJUST)
        header += " :"

        # Coloring (header)
        if self.HEADER_CLR:
            header = self.HEADER_CLR(header)
        # Coloring (warning)
        if warning:
            warning = text.bold_yellow("[" + warning + "]")
            # Coloring (content)
            # Use red for content coloring if warning message is given
            content = text.bold_red(content)
        elif self.CONTENT_CLR:
            content = self.CONTENT_CLR(content)

        # Build and print out message
        if warning:
            ctx = "%s %s %s" % (header, content, warning)
        else:
            ctx = "%s %s" % (header, content)
        print(ctx)


def generate_mask_str(avail_mask: int, freed_mask: int) -> Tuple[str, str]:
    """Generate pretty-print string for avail_mask and freed_mask

    Example:
       avail_mask : 0x7f80 (0b111111110000000)
       freed_mask : 0x0    (0b000000000000000)
    """

    # Hex strings for avail_mask and freed_mask
    ah = hex(avail_mask)
    fh = hex(freed_mask)
    maxlen = max(len(ah), len(fh))
    ah = ah.ljust(maxlen)  # fills ' '
    fh = fh.ljust(maxlen)

    # Binary strings for avail_mask and freed_mask
    ab = bin(avail_mask).replace("0b", "")
    fb = bin(freed_mask).replace("0b", "")
    maxlen = max(len(ab), len(fb))
    ab = ab.zfill(maxlen)  # fills '0'
    fb = fb.zfill(maxlen)

    avail_str = ah + text.bold_white(" (0b%s)" % ab)
    freed_str = fh + text.bold_white(" (0b%s)" % fb)
    return (avail_str, freed_str)


def generate_slot_map(meta: Dict, mask_index: int | None = None) -> str:
    """Generate a map-like string to display the status of all slots in a group.

    If mask_index is set, mask the specified slot in status map.

    Example:
       Slot status map: UUUAAAAFFUUUUUUU[U]UUUUUUUUUUUUU (from slot 29 to slot 0)
        (U: Inuse / A: Available / F: Freed)
    """

    legend = " (%s: Inuse / %s: Available / %s: Freed)" % (
        text.bold_white("U"),
        text.bold_green("A"),
        text.bold_red("F"),
    )

    avail_mask = int(meta["avail_mask"])
    freed_mask = int(meta["freed_mask"])
    slot_count = int(meta["last_idx"]) + 1

    # Generate slot status map
    mapstr = ""
    for idx in range(slot_count):
        avail = avail_mask & 1
        freed = freed_mask & 1
        if not freed and not avail:
            # Inuse
            s = text.bold_white("U")
        elif not freed and avail:
            # Available
            s = text.bold_green("A")
        elif freed and not avail:
            # Freed
            s = text.bold_red("F")
        else:
            s = "?"
        # Mask the slot with index `mask_index` in the map
        if idx == mask_index:
            s = "[" + s + "]"
        mapstr = s + mapstr

        avail_mask >>= 1
        freed_mask >>= 1

    if slot_count > 1:
        mapstr += " (from slot %s to slot %s)" % (
            text.bold_blue(str(slot_count - 1)),
            text.bold_blue("0"),
        )

    output = text.bold_magenta("\nSlot status map: ") + mapstr + "\n" + legend
    return output


class MuslMallocngMemoryAllocator(pwndbg.aglib.heap.heap.MemoryAllocator):
    # fmt: off
    size_classes = [
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 12, 15,
        18, 20, 25, 31,
        36, 42, 50, 63,
        72, 84, 102, 127,
        146, 170, 204, 255,
        292, 340, 409, 511,
        584, 682, 818, 1023,
        1169, 1364, 1637, 2047,
        2340, 2730, 3276, 4095,
        4680, 5460, 6552, 8191,
    ]
    # fmt: on

    def __init__(self) -> None:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n40
        # `ctx` (or `__malloc_context`) contains mallocng internal status (such as `active` and `free_meta_head`)
        self.ctx = None

    def check_mallocng(
        self,
    ) -> bool:
        """Check if mallocng is availble on current environment

        It simply checks if `__malloc_context` symbol is existed. If so, set the symbol value found as `self.ctx`.
        """
        sv = pwndbg.dbg.selected_inferior().symbol_address_from_name("__malloc_context")
        if sv is None:
            err_msg = """\
    ERROR: can't find musl-libc debug symbols!

    muslheap.py currently requires musl-libc 1.2.1+ with debug symbols installed.

    Either debug symbols are not installed or broken, or a libc without mallocng support (e.g. musl-libc < 1.2.1 or glibc) is used."""
            print(message.error(err_msg))
            return False
        else:
            self.ctx = pwndbg.aglib.memory.get_typed_pointer_value("struct malloc_context", sv)
        return True

    def get_libcbase(self) -> int | None:
        """Find and get musl libc.so base address from current memory mappings"""

        # FIXME: check for any other alternative names for the musl-libc library?
        soname_pattern = [
            r"^ld-musl-.+\.so\.1$",
            r"^libc\.so$",
            r"^libc\.musl-.+\.so\.1$",
        ]

        for mapping in pwndbg.aglib.vmmap.get():
            objfile = mapping.objfile
            if not objfile or objfile.startswith("["):
                continue
            objfn = Path(objfile).name
            for pattern in soname_pattern:
                if re.match(pattern, objfn):
                    return mapping.vaddr

        print(message.warn("Warning: can't find musl-libc in memory mappings!\n"))

        return None

    def get_group_type(self) -> pwndbg.dbg_mod.Value | None:
        """Find the struct group indirectly using the meta group

        There is another common `struct group` in grp.h that complicates pulling out the musl mallocng `struct group`,
        because gdb will favour the first one it finds. And I'm also not sure that we want to rely on a specific context
        block to pass to lookup_type. So since we know meta use is what we want, we just pull it from there.

        FIXME: This should probably be abstracted to be a helper in pwndbg.aglib.typeinfo
        """

        meta_type = pwndbg.aglib.typeinfo.lookup_types("struct meta")
        if meta_type is None:
            print(message.error("Type 'struct meta' not found."))
            return None
        # Purposely fuzzy find the member in case meta ever changes
        group_type = None
        for field in meta_type.fields():
            if str(field.type).startswith("struct group *"):
                group_type = field.type.target()
                break
        if group_type is None:
            print(message.error("Type 'struct group' not found in the 'meta' structure."))
            return None
        return group_type

    def get_stride(self, g: Dict) -> int | None:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n175

        last_idx = int(g["last_idx"])
        maplen = int(g["maplen"])
        sizeclass = int(g["sizeclass"])

        if not last_idx and maplen:
            return maplen * 4096 - mallocng.UNIT
        elif sizeclass < 48:
            return self.size_classes[sizeclass] * mallocng.UNIT
        else:
            # Return None if we failed to get stride
            return None

    def is_bouncing(self, sc: int) -> bool:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n283

        return (sc - 7 < 32) and int(self.ctx["bounces"][sc - 7]) >= 100

    def okay_to_free(self, g: Dict) -> bool:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/free.c?h=v1.2.2#n38

        if not g["freeable"]:
            return False

        sc = int(g["sizeclass"])
        cnt = int(g["last_idx"]) + 1
        usage = int(self.ctx["usage_by_class"][sc])
        stride = self.get_stride(g)

        if (
            sc >= 48
            or stride < mallocng.UNIT * self.size_classes[sc]
            or (not g["maplen"])
            or g["next"] != g
            or (not self.is_bouncing(sc))
            or (9 * cnt <= usage and cnt < 20)
        ):
            return True

        return False

    def search_chain(self, p: pwndbg.dbg_mod.Value) -> List:
        """Find slots where `p` is inside by traversing `ctx.meta_area_head` chain"""

        p = int(p)

        result = []
        try:
            # Traverse every meta object in `meta_area_head` chain
            meta_area = self.ctx["meta_area_head"]
            while int(meta_area):
                for i in range(int(meta_area["nslots"])):
                    meta = meta_area["slots"][i]
                    if not meta["mem"]:
                        # Skip unused
                        continue
                    stride = self.get_stride(meta)
                    if not stride:
                        # Skip invaild stride
                        continue
                    storage = int(meta["mem"]["storage"].address)
                    slot_count = int(meta["last_idx"]) + 1
                    group_start = int(meta["mem"])
                    group_end = storage + slot_count * stride - mallocng.IB
                    # Check if `p` is in the range of the group owned by this meta object
                    if p >= group_start and p < group_end:
                        if p >= (storage - mallocng.IB):
                            # Calculate the index of the slot where `p` is inside
                            slot_index = (p - (storage - mallocng.IB)) // stride
                        else:
                            # `p` is above the first slot, which means it's not inside of any slots in this group
                            # However, we set the slot index to 0 (the first slot). It's acceptable in most cases.
                            slot_index = 0
                        # We need a pointer (struct meta*), not the object itself
                        m = pwndbg.aglib.memory.get_typed_pointer("struct meta", meta.address)
                        if not m:
                            print(
                                text.bold_red("ERROR:"), "Failed to get the pointer of struct meta"
                            )
                            return result
                        result.append((m, slot_index))
                meta_area = meta_area["next"]
        except pwndbg.dbg_mod.Error as e:
            print(text.bold_red("ERROR search_chain():"), str(e))
            # raise
        return result

    # Called by mfindslot
    def display_ob_slot(self, p: pwndbg.dbg_mod.Value, meta: Dict, index: int) -> None:
        """Display slot out-of-band information

        This allows you to find information about uninitialized slots.
        """

        print(text.bold_white("\n=========== SLOT OUT-OF-BAND ============= "))
        printer = Printer(header_clr=text.bold_magenta, content_clr=text.bold_blue, header_rjust=10)
        P = printer.print

        stride = self.get_stride(meta)
        slot_start = int(meta["mem"]["storage"][stride * index].address)

        # Display the offset from slot to `p`
        offset = int(p) - slot_start
        if offset == 0:
            offset_tips = text.bold_white("0")
        elif offset > 0:
            offset_tips = text.bold_green("+" + hex(offset))
        else:
            offset_tips = text.bold_red(hex(offset))
        offset_tips = " (offset: %s)" % offset_tips

        P("address", text.bold_blue(hex(slot_start)) + offset_tips)
        P("index", index)
        P("stride", hex(stride))
        P("meta obj", text.magenta(hex(meta)))

        # Check slot status
        #
        # In mallocng, a slot can be in one of the following status:
        #  INUSE - slot is in use by user
        #  AVAIL - slot is can be allocated to user
        #  FREED - slot is freed
        #
        freed = (int(meta["freed_mask"]) >> index) & 1
        avail = (int(meta["avail_mask"]) >> index) & 1
        if not freed and not avail:
            # Calculate the offset to `user_data` field
            reserved_in_slot_head = (
                int(pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", slot_start - 3)) & 0xE0
            ) >> 5
            if reserved_in_slot_head == 7:
                cycling_offset = int(
                    pwndbg.aglib.memory.get_typed_pointer_value("uint16_t", slot_start - 2)
                )
                ud_offset = cycling_offset * mallocng.UNIT
            else:
                ud_offset = 0

            userdata_ptr = slot_start + ud_offset
            P(
                "status",
                "%s (userdata --> %s)"
                % (text.bold_white("INUSE"), text.bold_blue(hex(userdata_ptr))),
            )
            print("(HINT: use `mslotinfo %s` to display in-band details)" % hex(userdata_ptr))
        elif not freed and avail:
            P("status", text.bold_green("AVAIL"))
        elif freed and not avail:
            P("status", text.bold_red("FREED"))
        else:
            P("status", text.bold_white("?"))

    def parse_ib_meta(self, p: int) -> Dict:
        """Parse 4-byte in-band meta and offset32"""
        ib = {
            "offset16": pwndbg.aglib.memory.get_typed_pointer_value("uint16_t", p - 2),
            "index": int(pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", p - 3)) & 0x1F,
            "reserved_in_band": (
                int(pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", p - 3)) & 0xE0
            )
            >> 5,
            "overflow_in_band": pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", p - 4),
            "offset32": int(pwndbg.aglib.memory.get_typed_pointer_value("uint32_t", p - 8)),
        }
        return ib

    def display_ib_meta(self, p: int, ib: Dict) -> None:
        """Display in-band meta"""

        print(text.bold_white("============== IN-BAND META =============="))
        printer = Printer(header_clr=text.bold_green, content_clr=text.bold_blue, header_rjust=13)
        P = printer.print

        # IB: Check index
        index = ib["index"]
        if index < 0x1F:
            P("INDEX", index)
        else:
            P("INDEX", hex(index), "EXPECT: index < 0x1f")

        # IB: Check reserved_in_band
        reserved_in_band = ib["reserved_in_band"]
        if reserved_in_band < 5:
            P("RESERVED", reserved_in_band)
        elif reserved_in_band == 5:
            P("RESERVED", "5" + text.bold_magenta(" (Use reserved in slot end)"))
        elif reserved_in_band == 6:
            # This slot may be used as a group in mallocng internal.
            # It can't be freed by free() since `reserved_in_band` is illegal.
            # (See https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n269)
            P(
                "RESERVED",
                "%s %s %s"
                % (
                    text.bold_red("6"),
                    text.bold_yellow("[EXPECT: <= 5]"),
                    text.bold_magenta("(This slot may internally used as a group)"),
                ),
            )
        else:
            P("RESERVED", hex(reserved_in_band), "EXPECT: <= 5")

        # IB: Check overflow
        offset16 = int(ib["offset16"])
        overflow_in_band = int(ib["overflow_in_band"])
        if not overflow_in_band:
            group_ptr = p - (offset16 + 1) * mallocng.UNIT
            P("OVERFLOW", 0)
            P("OFFSET_16", "%s (group --> %s)" % (hex(offset16), hex(group_ptr)))
        else:
            # `offset32` can be used as the offset to group object
            # instead of `offset16` in IB if `overflow_in_band` is not NULL.
            # It is unlikely to happen in musl-libc for this feature
            # is only used in aligned_alloc() and comes with restriction:
            #   offset32  > 0xffff and offset16 == 0
            offset32 = ib["offset32"]
            group_ptr = p - (offset32 + 1) * mallocng.UNIT
            P(
                "OVERFLOW",
                text.bold_white(hex(overflow_in_band)) + text.bold_magenta(" (Use 32-bit offset)"),
            )
            if offset32 > 0xFFFF:
                P("OFFSET_32", "%s (group --> %s)" % (hex(offset32), hex(group_ptr)))
            else:
                P("OFFSET_32", hex(offset32), "EXPECT: > 0xffff")
            if offset16:
                P(
                    "OFFSET_16",
                    hex(offset16),
                    "EXPECT: *(uint16_t*)(%s) == 0]" % hex(p - 2),
                )

    def display_group(self, group: Dict) -> None:
        """Display group information"""

        print(
            text.bold_white("\n================= GROUP ================== ")
            + "(at %s)" % hex(int(group.address))
        )
        printer = Printer(header_clr=text.bold_cyan, content_clr=text.bold_blue, header_rjust=13)
        P = printer.print

        meta = group["meta"]
        P("meta", hex(meta))
        P("active_idx", int(group["active_idx"]))
        if meta == 0:
            print(message.warn("WARNING: group.meta is NULL. Likely unintialized IB data."))

    def display_meta(self, meta: Dict, ib: Dict | None = None, index: int | None = None):
        """Display meta information

        This gets called in two contexts, one where ib is known and one where index
        is known.
        """

        # Careful here to avoid 'not index' test, as it can legitimately be 0
        if not ib and index is None:
            raise ValueError("display_meta() requires either ib or index")
        if meta == 0:
            print(message.warn("WARNING: display_meta() can't parse NULL meta object"))
            return
        group = meta["mem"].dereference()

        if ib:
            index = ib["index"]
            if not int(ib["overflow_in_band"]):
                offset = int(ib["offset16"])
            else:
                offset = int(ib["offset32"])

        print(
            text.bold_white("\n================== META ================== ") + "(at %s)" % hex(meta)
        )
        printer = Printer(header_clr=text.bold_magenta, content_clr=text.bold_blue, header_rjust=13)
        P = printer.print

        # META: Check prev, next (no validation)
        P("prev", hex(meta["prev"]))
        P("next", hex(meta["next"]))

        # META: Check mem
        mem = meta["mem"]
        if int(group.address) == int(mem):
            P("mem", hex(mem))
        else:
            P("mem", hex(mem), "EXPECT: 0x%lx" % int(group.address))

        # META: Check last_idx
        last_idx = int(meta["last_idx"])
        if index <= last_idx:
            P("last_idx", last_idx)
        else:
            P("last_idx", last_idx, "EXPECT: index <= last_idx")

        avail_mask = int(meta["avail_mask"])
        freed_mask = int(meta["freed_mask"])
        avail_str, freed_str = generate_mask_str(avail_mask, freed_mask)

        # META: Check avail_mask
        if ib is None or not (avail_mask & (1 << index)):
            P("avail_mask", avail_str)
        else:
            # If we have in-band data, assume we are looking at an in-use chunk,
            # otherwise fetched IB data could be invalid
            P("avail_mask", avail_str, "EXPECT: !(avail_mask & (1<<index))")

        # META: Check freed_mask
        if ib is None or not (freed_mask & (1 << index)):
            P("freed_mask", freed_str)
        else:
            # If we have in-band data, assume we are looking at an in-use chunk,
            # otherwise fetched IB data could be invalid
            P("freed_mask", freed_str, "EXPECT: !(freed_mask & (1<<index))")

        # META: Check area->check
        area = pwndbg.aglib.memory.get_typed_pointer_value("struct meta_area", int(meta) & -4096)

        secret = int(self.ctx["secret"])
        if int(area["check"]) == secret:
            P("area->check", hex(area["check"]))
        else:
            P(
                "area->check",
                hex(area["check"]),
                "EXPECT: *(0x%lx) == 0x%lx" % (int(meta) & -4096, secret),
            )

        # META: Check sizeclass
        sc = int(meta["sizeclass"])
        if sc == 63:  # A special sizeclass for single slot group allocations
            stride = self.get_stride(meta)
            if stride:
                P("sizeclass", "63 " + text.bold_white(" (stride: 0x%lx)" % stride))
            else:
                P("sizeclass", "63 " + text.bold_white(" (stride: ?)"))
        elif sc < 48:
            sc_stride = mallocng.UNIT * self.size_classes[sc]
            real_stride = self.get_stride(meta)
            if not real_stride:
                stride_tips = text.bold_white("(stride: 0x%lx, real_stride: ?)" % sc_stride)
            elif sc_stride != real_stride:
                stride_tips = text.bold_white(
                    "(stride: 0x%lx, real_stride: 0x%lx)" % (sc_stride, real_stride)
                )
            else:
                stride_tips = text.bold_white("(stride: 0x%lx)" % sc_stride)
            bad = 0
            # Validation requires in-band data, which we won't have from mfindslot
            if ib:
                if not (int(offset) >= self.size_classes[sc] * index):
                    P(
                        "sizeclass",
                        "%d %s" % (sc, stride_tips),
                        "EXPECT: offset >= self.size_classes[sizeclass] * index",
                    )
                    bad = 1
                if not (int(offset) < self.size_classes[sc] * (index + 1)):
                    P(
                        "sizeclass",
                        "%d %s" % (sc, stride_tips),
                        "EXPECT: offset < self.size_classes[sizeclass] * (index + 1)",
                    )
                    bad = 1
            if not bad:
                P("sizeclass", "%d %s" % (sc, stride_tips))
        else:
            P("sizeclass", sc, "EXPECT: sizeclass < 48 || sizeclass == 63")

        # META: Check maplen
        maplen = int(meta["maplen"])
        if maplen:
            if offset <= (maplen * (4096 // mallocng.UNIT)) - 1:
                P("maplen", hex(maplen))
            else:
                P(
                    "maplen",
                    hex(maplen),
                    "EXPECT: offset <= maplen * %d - 1" % (4096 // mallocng.UNIT),
                )
        else:
            P("maplen", 0)

        # META: Check freeable
        P("freeable", int(meta["freeable"]))

        # META: Check group allocation method
        if not meta["freeable"]:
            # This group is a donated memory.
            # That is, it was placed in an unused RW memory area from a object file loaded by ld.so.
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/donate.c?h=v1.2.2#n10)

            group_addr = int(group.address)

            # Find out which object file in memory mappings donated this memory.
            vmmap = pwndbg.aglib.vmmap.get()
            for mapping in vmmap:
                start = mapping.vaddr
                end = mapping.vaddr + mapping.memsz
                objfile = mapping.objfile
                if not objfile or objfile.startswith("["):
                    continue
                if group_addr > start and group_addr < end:
                    method = "donated from %s" % text.bold_white(objfile)
                    break
            else:
                method = "donated from an unknown object file"
        elif not meta["maplen"]:
            # XXX: Find out which group is used.
            method = text.bold_white("another group's slot")
        else:
            method = text.bold_white("individual mmap")
        print(text.bold_magenta("\nGroup allocation method : ") + method)

        # Display slot status map
        print(generate_slot_map(meta, index))

    def display_nontrivial_free(self, ib: Dict, group: Dict) -> None:
        """Display the result of nontrivial_free()"""

        printer = Printer(header_clr=text.bold_magenta, content_clr=text.bold_green)
        P = printer.print
        print()

        print_dq = print_fg = print_fm = 0

        meta = group["meta"]
        sizeclass = int(meta["sizeclass"])
        index = int(ib["index"])

        mask = int(meta["freed_mask"]) | int(meta["avail_mask"])
        slf = (1 << index) & mallocng.UINT32_MASK
        if mask + slf == (2 << int(meta["last_idx"])) - 1 and self.okay_to_free(meta):
            if meta["next"]:
                if sizeclass < 48:
                    P("Result of nontrivial_free()", "dequeue, free_group, free_meta")
                else:
                    P(
                        "Result of nontrivial_free()",
                        "dequeue, free_group, free_meta",
                        "EXPECT: sizeclass < 48",
                    )
                print_dq = print_fg = print_fm = 1
            else:
                P("Result of nontrivial_free()", "free_group, free_meta")
                print_fg = print_fm = 1
        elif not mask and self.ctx["active"][sizeclass] != meta:
            if sizeclass < 48:
                P("Result of nontrivial_free()", "queue (active[%d])" % sizeclass)
            else:
                P(
                    "Result of nontrivial_free()",
                    "queue (active[%d])" % sizeclass,
                    "EXPECT: sizeclass < 48",
                )
        else:
            P("Result of nontrivial_free()", text.bold_white("Do nothing"))

        # dequeue
        if print_dq:
            print(text.bold_green("  dequeue:"))
            prev_next = text.magenta("*" + hex(meta["prev"]["next"].address))
            prev_next = text.bold_blue("prev->next(") + prev_next + text.blue(")")
            next_prev = text.magenta("*" + hex(meta["next"]["prev"].address))
            next_prev = text.bold_blue("next->prev(") + next_prev + text.bold_blue(")")
            next = text.bold_blue("next(") + text.magenta(hex(meta["next"])) + text.bold_blue(")")
            prev = text.bold_blue("prev(") + text.magenta(hex(meta["prev"])) + text.bold_blue(")")
            print("  \t%s = %s" % (prev_next, next))  # prev->next(XXX) = next(XXX)
            print("  \t%s = %s" % (next_prev, prev))  # next->prev(XXX) = prev(XXX)
        # free_group
        if print_fg:
            print(text.bold_green("  free_group:"))
            if meta["maplen"]:
                free_method = "munmap (len=0x%lx)" % (int(meta["maplen"]) * 4096)
            else:
                free_method = "nontrivial_free()"
            print(
                " \t%s%s%s%s"
                % (
                    text.bold_blue("group object at "),
                    text.magenta(hex(int(meta["mem"]))),
                    text.bold_blue(" will be freed by "),
                    text.bold_cyan(free_method),
                )
            )
        # free_meta
        if print_fm:
            print(text.bold_green("  free_meta:"))
            print(
                " \t%s%s%s"
                % (
                    text.bold_blue("meta object at "),
                    text.magenta(hex(meta)),
                    text.bold_blue(" will be freed and inserted into free_meta chain"),
                )
            )

    # Called by mslotinfo.
    def display_ib_slot(self, p: pwndbg.dbg_mod.Value, meta: Dict, ib: Dict) -> None:
        """Display slot in-band information

        This expects the slot to be in-use and tries to parse it's in-band data.

        If the ib data isn't initialized yet, it will fail.
        """

        index = ib["index"]
        stride = self.get_stride(meta)
        slot_start = meta["mem"]["storage"][stride * index].address
        slot_end = int(slot_start + stride - mallocng.IB)

        print(
            text.bold_white("\n============= SLOT IN-BAND =============== ")
            + "(at %s)" % hex(slot_start)
        )

        printer = Printer(header_clr=text.bold_blue, content_clr=text.bold_white, header_rjust=20)
        P = printer.print

        # SLOT: Check cycling offset
        reserved_in_slot_head = (
            int(pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", slot_start - 3)) & 0xE0
        ) >> 5
        if reserved_in_slot_head == 7:
            # If `R` is 7, it indicates that slot header is used to store cycling offset (in `OFF` field)
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n217)
            cycling_offset = pwndbg.aglib.memory.get_typed_pointer_value(
                "uint16_t", slot_start - 2
            )  # `OFF`
        else:
            # Else, slot header is now occupied by in-band meta.
            # In this case, `userdata` will be located at the beginning of slot.
            cycling_offset = 0
        userdata_ptr = slot_start + cycling_offset * mallocng.UNIT
        P(
            "cycling offset",
            "%s (userdata --> %s)" % (hex(cycling_offset), hex(userdata_ptr)),
        )

        # SLOT: Check reserved
        reserved_in_band = int(ib["reserved_in_band"])
        if reserved_in_band < 5:
            reserved = reserved_in_band
        elif reserved_in_band == 5:
            reserved_in_slot_end = int(
                pwndbg.aglib.memory.get_typed_pointer_value("uint32_t", slot_end - 4)
            )
            if reserved_in_slot_end >= 5:
                reserved = reserved_in_slot_end
            else:
                P("reserved (slot end)", hex(reserved_in_slot_end), "EXPECT: >= 5")
                reserved = -1
        else:
            P("reserved (in-band)", hex(reserved_in_band), "EXPECT: <= 5")
            reserved = -1

        # SLOT: Check nominal size
        if reserved != -1:
            if reserved <= slot_end - int(p):
                nominal_size = slot_end - reserved - int(p)
                P("nominal size", hex(nominal_size))
                P("reserved size", hex(reserved))
            else:
                P("nominal size", "N/A (reserved size is invaild)")
                P("reserved size", hex(reserved), "EXPECT: <= %s" % hex(slot_end - int(p)))
                reserved = -1
        else:
            P("nominal size", "N/A (reserved size is invaild)")

        # SLOT: Check OVERFLOWs
        if reserved != -1:
            ud_overflow = int(
                pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", slot_end - reserved)
            )
            if not ud_overflow:
                P("OVERFLOW (user data)", 0)
            else:
                P(
                    "OVERFLOW (user data)",
                    hex(ud_overflow),
                    "EXPECT: *(uint8_t*)(%s) == 0" % hex(slot_end - reserved),
                )
            if reserved >= 5:
                rs_overflow = pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", slot_end - 5)
                if not rs_overflow:
                    P("OVERFLOW  (reserved)", 0)
                else:
                    P(
                        "OVERFLOW  (reserved)",
                        hex(rs_overflow),
                        "EXPECT: *(uint8_t*)(%s) == 0" % hex(slot_end - 5),
                    )
        else:
            P("OVERFLOW (user data)", "N/A (reserved size is invaild)")
            P("OVERFLOW  (reserved)", "N/A (reserved size is invaild)")
        ns_overflow = int(pwndbg.aglib.memory.get_typed_pointer_value("uint8_t", slot_end))
        if not ns_overflow:
            P("OVERFLOW (next slot)", 0)
        else:
            P(
                "OVERFLOW (next slot)",
                hex(ns_overflow),
                "EXPECT: *(uint8_t*)(%s) == 0" % hex(slot_end),
            )
