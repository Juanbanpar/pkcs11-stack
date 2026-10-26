# SPDX-License-Identifier: MIT OR Apache-2.0
"""Read native SoftHSM mechanism IDs independently of cryptoki's conversion."""
import ctypes
import sys

module = ctypes.CDLL(sys.argv[1])
ulong = ctypes.c_ulong
module.C_Initialize.argtypes = [ctypes.c_void_p]
module.C_Initialize.restype = ulong
module.C_GetMechanismList.argtypes = [ulong, ctypes.POINTER(ulong), ctypes.POINTER(ulong)]
module.C_GetMechanismList.restype = ulong
module.C_Finalize.argtypes = [ctypes.c_void_p]
module.C_Finalize.restype = ulong

assert module.C_Initialize(None) == 0
try:
    slot = ulong(int(sys.argv[2]))
    count = ulong()
    assert module.C_GetMechanismList(slot, None, ctypes.byref(count)) == 0
    mechanisms = (ulong * count.value)()
    assert module.C_GetMechanismList(slot, mechanisms, ctypes.byref(count)) == 0
    for mechanism in mechanisms[:count.value]:
        print(mechanism)
finally:
    assert module.C_Finalize(None) == 0
