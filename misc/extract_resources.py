#!/usr/bin/env python3
import sys
import os.path
import pefile

def save(f: str, d: bytes):
    with open(f, 'wb') as fd:
        fd.write(d)

pe = pefile.PE(sys.argv[1])
resources = pe.DIRECTORY_ENTRY_RESOURCE.entries
for rdir in resources:
    if not rdir.id:
        continue
    for entry in rdir.directory.entries:
        for r in entry.directory.entries:
            vaddr = r.data.struct.OffsetToData
            size = r.data.struct.Size

            fname = f'{rdir.struct.Name}-{pefile.RESOURCE_TYPE.get(rdir.id)}.rsrc'
            dname = os.path.dirname(sys.argv[1])
            save(dname + "/" + fname, pe.get_data(vaddr, size))
