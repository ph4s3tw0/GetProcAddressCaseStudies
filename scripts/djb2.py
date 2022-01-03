from ctypes import c_uint64

def hash_djb2(s):    
   hash = 0x1337133713371337
   for x in s:
      hash = (( hash << 5) + hash) + ord(x)
   return c_uint64(hash)

lines = [
   "A_SHAFinal",
   "CsrAllocateCaptureBuffer",
   "DbgBreakPoint",
   "EtwProcessPrivateLoggerRequest",
   "KiRaiseUserExceptionDispatcher",
   "LdrAccessResource",
   "MD4Final",
   "_wcsnset_s",
   "abs",
   "bsearch",
   "ceil",
   "fabs",
   "iswctype",
   "labs",
   "mbstowcs",
   "pow",
   "qsort",
   "sin",
   "tan",
   "vDbgPrintEx",
   "wcscat"]

for name in lines:
   print(name + ": " + str(hex(hash_djb2(name).value)))