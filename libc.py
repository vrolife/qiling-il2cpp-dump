import io
from elftools.elf.elffile import ELFFile, DynamicSegment

def read_so(info, memory, soname):
    so_addr = 0
    so_end = 0
    so_data = io.BytesIO()

    for region in info["regions"]:
        file = region["file"]

        if so_addr == 0 and not file.endswith(soname):
            continue

        if so_addr == 0:
            so_addr = region['begin']
            so_end = region['end']
        else:
            if region['begin'] != so_end:
                break
            else:
                so_end = region['end']

        size = region["end"] - region["begin"]

        memory.seek(region["saved_offset"], 0)
        mem = memory.read(size)
        so_data.write(mem)
        del mem
    return so_data, so_addr, so_end

def get_funcs(info, memory, soname, names):
    data, addr, end = read_so(info, memory, soname)
    elf = ELFFile(data)

    for seg in elf.iter_segments(): # type: Segment
        if isinstance(seg, DynamicSegment):
            def get_sym(name):
                offset = seg.get_symbol_by_name(name)[0].entry.st_value
                if offset == 0:
                    raise KeyError(f'symbol not found: {name}')
                return addr + offset
            return list(map(get_sym, names))
