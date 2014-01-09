cimport ccapstone as cc
import ctypes
from capstone import x86, _cs_detail
import capstone

class CsDetail:

  def __init__(self, detail):
    self.detail = ctypes.cast(detail, ctypes.POINTER(_cs_detail))
    detail = self.detail.contents
    (self.prefix, self.segment, self.opcode, self.op_size, self.addr_size, \
                self.disp_size, self.imm_size, self.modrm, self.sib, self.disp, \
                self.sib_index, self.sib_scale, self.sib_base, self.operands) = x86.get_arch_info(detail.arch.x86)

cdef class CCsInsn:

  cdef cc.cs_insn _raw

  def __cinit__(self):
    pass

  @property
  def address(self):
    return self._raw.address

  @property
  def detail(self):
    #ptr = <size_t>self._raw.detail
    #return CsDetail(ptr)
    pass

cdef class CCs:

  cdef cc.csh csh

  def __cinit__(self, arch, mode):
    cc.cs_open(arch, mode, &self.csh)
    #cc.cs_option(self.csh, capstone.CS_OPT_DETAIL, capstone.CS_OPT_ON);

  def disasm(self, code, addr):
    cdef cc.cs_insn *allinsn
    res = cc.cs_disasm_ex(self.csh, code, len(code), addr, 0, &allinsn)

    for i from 0 <= i < res:
      dummy = CCsInsn()
      dummy._raw = allinsn[i]
      yield dummy


