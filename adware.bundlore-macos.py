#!/usr/bin/env python3
# extracts commands from 'Install Flash Player' (Adware.Bundlore/Bnodlero)
import angr
import claripy
import logging

# 0x00000001000037dc E855000000             call       imp___stubs__system        ; system
# 0x00000001000037f2 E83F000000             call       imp___stubs__system        ; system
system_addrs = [0x1000037dc, 0x1000037f2]

def create_output(addr, data):
    filename = f'{hex(addr)}.out'
    with open(filename, 'wb+') as fd:
        fd.write(data)
    print(f'{filename} created')

def main():
    angr.loggers.setall(logging.ERROR)
    proj  = angr.Project('Install Flash Player', auto_load_libs=False, load_debug_info=True)
    state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=system_addrs)
    for f in simgr.found:
        cmd_addr = f.solver.eval(f.regs.rdi)
        create_output(cmd_addr, f.mem[cmd_addr].string.concrete)
    return

if __name__ == '__main__':
    main()
