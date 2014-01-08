#!/usr/bin/python

# Simple benchmark for Capstone by disassembling random code. By Nguyen Anh Quynh, 2014

from capstone import *

#temp
from capstone.ccapstone import CCs

from time import time
from random import randint


def random_str(size):
    lst = [str(randint(0, 255)) for _ in xrange(size)]
    return "".join(lst)

def cs(md, data):
    insns = md.disasm(data, 0)
    # uncomment below line to speed up this function 200 times!
    # return
    for i in insns:
        if i.address == 0x100000:
            print i

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

md2 = CCs(CS_ARCH_X86, CS_MODE_32)

# warm up few times
for i in xrange(3):
    data = random_str(128)
    cs(md, data)

# start real benchmark
c_t = 0
c_t2 = 0
for i in xrange(10000):
    code = random_str(128)

    t1 = time()
    cs(md, code)
    c_t += time() - t1

    t1 = time()
    cs(md2, code)
    c_t2 += time() - t1


print "Capstone:", c_t, "seconds"
print "Capstone 2:", c_t2, "seconds"
