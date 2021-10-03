#!/usr/bin/env python3

from pwn import *
import angr
import claripy
import sys
import ipdb

# After "CALL scanf"
START = 0x400960
# Flag
FIND = 0x400B5D
# "Bad format!" and "Wrong!"
AVOID = [0x400BF7, 0x400BF0]
# Not fail cases, but don't continue execution
DEADEND = [0x400BFC, 0x400C01, 0x400C03, 0x400C0A, 0x400C0B, 0x400C20]

BUF_LEN = 104 * 8


class pass_hook(angr.SimProcedure):
    def run(self):
        print("! pass_hook")
        return


def main():
    with open(sys.argv[1], "rb") as f:
        asm = f.read()[0x960:]

    project = angr.load_shellcode(
        asm,
        "x86_64",
        start_offset=0,
        load_address=0x400960,
        support_selfmodifying_code=True,
    )
    state = project.factory.entry_state()

    memory = open("out.0x400000.mem", "rb").read()
    state.memory.store(0x400000, memory, disable_actions=True, inspect=False)
    state.memory.permissions(0x400000, 5)  # r-x

    memory = open("out.0x603000.mem", "rb").read()
    state.memory.store(0x603000, memory, disable_actions=True, inspect=False)
    state.memory.permissions(0x603000, 4)  # r--

    memory = open("out.0x604000.mem", "rb").read()
    state.memory.store(0x604000, memory, disable_actions=True, inspect=False)
    state.memory.permissions(0x604000, 6)  # rw-

    memory = open("out.0x7ffffffdd000.mem", "rb").read()
    state.memory.store(0x7FFFFFFDD000, memory, disable_actions=True, inspect=False)
    state.memory.permissions(0x7FFFFFFDD000, 6)  # rw-

    state.regs.rax = 0x4  # used for scanf parsed count check
    state.regs.rbx = 0x403350
    state.regs.rcx = 0x0
    state.regs.rdx = 0x0
    state.regs.rdi = 0x7FFFFFFFB930
    state.regs.rsi = 0x0
    state.regs.r8 = 0x4
    state.regs.r9 = 0x0
    state.regs.r10 = 0x7FFFF7C48AC0
    state.regs.r11 = 0x7FFFF7C493C0
    state.regs.r12 = 0x400830
    state.regs.r13 = 0x0
    state.regs.r14 = 0x0
    state.regs.r15 = 0x7FFFFFFFC5D8
    state.regs.rbp = 0x0
    state.regs.rsp = 0x7FFFFFFFBE70
    state.regs.rip = 0x400960

    sym_data = state.solver.BVS("v1", 64)
    state.memory.store(
        state.regs.rsp + 0x10, sym_data, disable_actions=True, inspect=False
    )
    sym_data = state.solver.BVS("v2", 64)
    state.memory.store(
        state.regs.rsp + 0x14, sym_data, disable_actions=True, inspect=False
    )
    sym_data = state.solver.BVS("v3", 64)
    state.memory.store(
        state.regs.rsp + 0x18, sym_data, disable_actions=True, inspect=False
    )
    sym_data = state.solver.BVS("v4", 64)
    state.memory.store(
        state.regs.rsp + 0x1C, sym_data, disable_actions=True, inspect=False
    )

    # Skip libc handlers
    project.hook(0x400790, pass_hook())
    project.hook(0x4007A0, pass_hook())
    project.hook(0x4007B0, pass_hook())
    project.hook(0x4007C0, pass_hook())
    project.hook(0x4007D0, pass_hook())
    project.hook(0x4007E0, pass_hook())
    project.hook(0x4007F0, pass_hook())
    project.hook(0x400800, pass_hook())
    project.hook(0x400810, pass_hook())
    project.hook(0x400C20, pass_hook())

    # Sanity checking the start address instruction
    print(project.factory.block(0x400960).bytes)
    assert project.factory.block(0x400960).bytes[0] == 0x83

    sm = project.factory.simgr(state)
    while sm.active:
        print(sm, sm.active)
        for active in sm.active:
            project.factory.block(active.addr, backup_state=active).pp()
            if active.addr in [FIND]:
                ipdb.set_trace()
        sm.step()

        # Don't run fail cases, libc, stack, etc...
        sm.stash(
            from_stash="active",
            to_stash="avoid",
            filter_func=lambda s: s.addr in AVOID or s.addr > 0x7FFFF7AF0000,
        )
        # Don't run code after the flag check end
        sm.stash(
            from_stash="active",
            to_stash="deadend",
            filter_func=lambda s: s.addr in DEADEND or s.addr > 0x400C28,
        )

    for errored in ex.errored:
        error = errored.error
        print(error.bbl_addr)
        print(error.stmt_idx)
        print(error)

    ipdb.set_trace()


if __name__ == "__main__":
    main()
