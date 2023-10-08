import sys
import json
import struct
import ctypes
import argparse
import pathlib
from unicorn import *
from unicorn.arm64_const import *
from qiling import Qiling
from qiling.const import QL_VERBOSE

import libc

parser = argparse.ArgumentParser()
parser.add_argument('prefix', type=str)
args = parser.parse_args()

info_pathname = pathlib.Path(f"{args.prefix}.json")

with open(info_pathname, "r") as fp:
    memory_info = json.load(fp)

memory_data = open(info_pathname.parent / memory_info['memory_file'], "rb")

def load_memory(mu):
    idx = 0

    regions = []
    for region in memory_info["regions"]:
        r = dict(region)

        file = region["file"]
        if file.startswith("/dev/k"):
            continue

        if "stack" in r["desc"]:
            continue

        if "[anon:dalvik-LinearAlloc]" in r["desc"]:
            continue

        if '/system/fonts/' in r["desc"]:
            continue

        if file.endswith("jar") or file.endswith("apk") or file.endswith("hyb"):
            continue

        if len(regions) == 0:
            regions.append(r)
            continue

        if r['file'] == regions[-1]["file"] and r['begin'] == regions[-1]["end"] and regions[-1]["saved_size"] == (regions[-1]["end"] - regions[-1]["begin"]):
            regions[-1]["end"] = r['end']
            regions[-1]["saved_size"] += r['saved_size']
            continue
        regions.append(r)
    print(len(regions))

    for region in regions:
        size = region["end"] - region["begin"]
        mu.mem_map(region["begin"], size)

        if region["saved_size"] != 0:
            memory_data.seek(region["saved_offset"], 0)
            mem = memory_data.read(region["saved_size"])
            mu.mem_write(region["begin"], mem)
            del mem

        print(f"Load {idx}/{len(memory_info['regions'])} {region['begin']:x}-{region['end']:x} {size} {region['file']} {region['desc']}")
        idx += 1
        
END_ADDRESS = 0x55aa55aa55aa55aa
STACK_ADDRESS = 0x8FFF800000000000
STACK_SIZE = 0x8000000
TLS_ADDRESS = STACK_ADDRESS + 0x1000
TCB_ADDRESS = TLS_ADDRESS + 0x1000
BIONIC_TLS_ADDRESS = TCB_ADDRESS + 0x1000

ql = Qiling(["dump.elf"],
    rootfs='./rootfs', 
    verbose=QL_VERBOSE.OFF, 
    profile='./dump.ql',
    ostype="Linux",
    archtype="ARM64")

def hook_fetch_unmapped(mu: Uc, access, addr, size, value, user_data):
    print(f"0x{mu.reg_read(UC_ARM64_REG_PC):x}: fetch 0x{addr:x} size: {size} ")

def hook_read_unmapped(mu: Uc, access, addr, size, value, user_data):
    print(f"0x{mu.reg_read(UC_ARM64_REG_PC):x}: read 0x{addr:x} size: {size} ")

def hook_write_unmapped(mu: Uc, access, addr, size, value, user_data):
    print(f"0x{mu.reg_read(UC_ARM64_REG_PC):x}: write 0x{addr:x} size: {size} value: {hex(value)}")

ql.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_fetch_unmapped)
ql.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_read_unmapped)
ql.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_write_unmapped)

# TLS
tls = struct.pack('<QQQQQQQQQ',
    BIONIC_TLS_ADDRESS, # BIONIC_TLS
    0, # DTV
    TCB_ADDRESS, # THREAD ID
    # 0x778ca4d508-16,
    0, # APP
    0, # OGL
    0, # OGL API
    0, # STACK GUARD
    0, # SANITIZER
    0, # ART THREAD TLS
)
ql.uc.mem_write(TLS_ADDRESS, tls)

class pthread_attr_t(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("stack_base", ctypes.c_void_p),
        ("stack_size", ctypes.c_size_t),
    ]

class pthread_internal_t(ctypes.Structure):
    _fields_ = [
        ("next", ctypes.c_void_p),
        ("prev", ctypes.c_void_p),
        ("tid", ctypes.c_int),
        ("cache_pid_and_vforked", ctypes.c_uint32),
        ("attr", pthread_attr_t),
    ]

thread_attr = pthread_attr_t(0, STACK_ADDRESS, STACK_SIZE)
thread = pthread_internal_t(0, 0, 0, 0, thread_attr)
ql.uc.mem_write(TCB_ADDRESS, bytes(thread))

ql.uc.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_ADDRESS + 8)

HEAP_ADDRESS = STACK_ADDRESS + 0x8000

# def __cxa_throw(*args):
#     print(f"throw exception... 0x{ql.uc.reg_read(UC_ARM64_REG_LR):x}")
#     sys.exit(-1)
#
# __cxa_throw_addr, = libc.get_funcs(memory_info, memory_data, 'libil2cpp.so', ['__cxa_throw'])
# print(f"__cxa_throw_addr {__cxa_throw_addr}")
# ql.uc.hook_add(UC_HOOK_CODE, __cxa_throw, None, __cxa_throw_addr, __cxa_throw_addr + 4)

load_memory(ql.uc)

def malloc(*args):
    global HEAP_ADDRESS
    sz = ql.uc.reg_read(UC_ARM64_REG_X0)
    ql.uc.reg_write(UC_ARM64_REG_X0, HEAP_ADDRESS)
    HEAP_ADDRESS += (sz + 15) & ~15
    # print(f"[py] malloc {sz}")

def free(*args):
    pass

def calloc(*args):
    global HEAP_ADDRESS
    n = ql.uc.reg_read(UC_ARM64_REG_X0)
    sz = ql.uc.reg_read(UC_ARM64_REG_X1) * n
    ql.uc.reg_write(UC_ARM64_REG_X0, HEAP_ADDRESS)
    HEAP_ADDRESS += (sz + 15) & ~15
    # print(f"[py] calloc {sz}")

def realloc(*args):
    global HEAP_ADDRESS
    ptr = ql.uc.reg_read(UC_ARM64_REG_X0)
    sz = ql.uc.reg_read(UC_ARM64_REG_X1)
    # print(f"[py] realloc 0x{ptr:x} {sz}")
    if ptr != 0:
        if sz == 0:
            # free
            return
        data = ql.uc.mem_read(ptr, sz)
        ql.uc.mem_write(HEAP_ADDRESS, bytes(data))
    ql.uc.reg_write(UC_ARM64_REG_X0, HEAP_ADDRESS)
    HEAP_ADDRESS += (sz + 15) & ~15

MALLOC_ADDR, FREE_ADDR, CALLOC_ADDR, REALLOC_ADDR = libc.get_funcs(memory_info, memory_data, 'libc.so', ['malloc', 'free', 'calloc', 'realloc'])
DLSYM_ADDR, = libc.get_funcs(memory_info, memory_data, 'libdl.so', ['dlsym'])

IL2CPP_BASE_DATA, IL2CPP_BASE_ADDR, IL2CPP_BASE_END = libc.read_so(memory_info, memory_data, "libil2cpp.so")

print(f'malloc 0x{MALLOC_ADDR:x}')
print(f'free 0x{FREE_ADDR:x}')
print(f'calloc 0x{CALLOC_ADDR:x}')
print(f'dlsym 0x{DLSYM_ADDR:x}')

dlsym_code = ql.uc.mem_read(DLSYM_ADDR, 16 * 4)
# mov lr, x2 => mov x2, x2
ql.uc.mem_write(DLSYM_ADDR + dlsym_code.find(bytes.fromhex('E2 03 1E AA')), bytes.fromhex('e2 03 02 aa'))

ql.uc.mem_write(MALLOC_ADDR, b'\xC0\x03\x5F\xD6') # ret
ql.uc.mem_write(FREE_ADDR, b'\xC0\x03\x5F\xD6') # ret
ql.uc.mem_write(CALLOC_ADDR, b'\xC0\x03\x5F\xD6') # ret
ql.uc.mem_write(REALLOC_ADDR, b'\xC0\x03\x5F\xD6') # ret

ql.uc.hook_add(UC_HOOK_CODE, malloc, None, MALLOC_ADDR, MALLOC_ADDR + 4)
ql.uc.hook_add(UC_HOOK_CODE, free, None, FREE_ADDR, FREE_ADDR + 4)
ql.uc.hook_add(UC_HOOK_CODE, calloc, None, CALLOC_ADDR, CALLOC_ADDR + 4)
ql.uc.hook_add(UC_HOOK_CODE, realloc, None, REALLOC_ADDR, REALLOC_ADDR + 4)

ql.uc.reg_write(UC_ARM64_REG_X0, DLSYM_ADDR)
ql.uc.reg_write(UC_ARM64_REG_X1, IL2CPP_BASE_ADDR)
ql.uc.reg_write(UC_ARM64_REG_LR, END_ADDRESS)

try:
    ql.run(end=END_ADDRESS)
except:
    pc = ql.uc.reg_read(UC_ARM64_REG_PC) - 8
    print(f"pc 0x{pc:x}")
    dis = ql.arch.disassembler
    code = ql.uc.mem_read(pc, 4 * 8)
    print(code.hex())
    for i in list(dis.disasm(code, pc)):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    raise

"""
patch venv/lib/python3.10/site-packages/qiling/arch/arm64.py
    @cached_property
    def uc(self) -> Uc:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
        return uc
"""
