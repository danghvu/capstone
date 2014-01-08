cimport ccapstone as cc

cdef class CCsInsn:

  cdef cc.cs_insn _raw

  def __cinit__(self):
    pass

  @property
  def address(self):
    return self._raw.address

cdef class CCs:

  cdef cc.csh csh

  def __cinit__(self, arch, mode):
    cc.cs_open(arch, mode, &self.csh)

  def disasm(self, code, addr):
    cdef cc.cs_insn *allinsn
    res = cc.cs_disasm_ex(self.csh, code, len(code), addr, 0, &allinsn)

    for i in xrange(res):
      dummy = CCsInsn()
      dummy._raw = allinsn[i]
      yield dummy


