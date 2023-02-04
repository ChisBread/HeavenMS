# -*- coding: utf-8 -*-
import binascii
import pefile

import shutil

def find_all(a_str, sub):
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1:
            return
        yield start
        start += len(sub)  # use start += 1 to find overlapping matches


SW=1280#not support now
SH=800
PEfile_Path = "./Maplestory.exe"
pe = pefile.PE(PEfile_Path)
for line in open('height.txt'):
  addr, offset, target_val, dist_expr = [int(eval(x)) for x in line.split('\t')[:4]]
  val = int.from_bytes(pe.get_data(addr-0x00400000+offset,4), byteorder='little', signed=True)
  print("addr:0x%x val:0x%x is match:%s"%(addr, val, val==target_val))
  if val==target_val:
    pe.set_dword_at_rva(addr-0x00400000+offset, dist_expr)
    val = int.from_bytes(pe.get_data(addr-0x00400000+offset,4), byteorder='little', signed=True)
    if val==dist_expr:
      print("addr:0x%x ->0x%x writed"%( addr, dist_expr))
    else:
      exit(-1)
  else:
    exit(-1)
pe.write(filename="./Maplestory.%sx%s.exe"%(SW,SH))
print('done')