import os
import ctypes
import struct
from datetime import datetime

HANDLE = ctypes.c_void_p
HMODULE = HANDLE
LPCSTR = LPSTR = ctypes.c_char_p
BOOL = ctypes.c_long
BYTE = ctypes.c_ubyte
SIZE_T = ctypes.c_size_t
DWORD = ctypes.c_ulong
ULONG = ctypes.c_ulong
ALG_ID = ctypes.c_ulong
LPBUFFER = ctypes.POINTER(ctypes.c_char)

# this is the Win32 Epoch time for when Unix Epoch time started. It is in
# hundreds of nanoseconds.
EPOCH_AS_FILETIME = 116444736000000000
# This is the divider/multiplier for converting nanoseconds to
# seconds and vice versa
HUNDREDS_OF_NANOSECONDS = 10000000


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", DWORD),
                ("dwHighDateTime", DWORD)]

    @property
    def unix_epoch_seconds(self):
        val = (self.dwHighDateTime << 32) + self.dwLowDateTime
        return (val - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS

    def __str__(self):
        dt = datetime.datetime.utcfromtimestamp(self.unix_epoch_seconds)
        return dt.strftime('%c')


_FILETIME = FILETIME
PFILETIME = ctypes.POINTER(_FILETIME)


def RaiseIfZero(result, func=None, arguments=()):
    if not result:
        raise ctypes.WinError()
    return result


#
# HMODULE WINAPI LoadLibrary(
#   _In_ LPCTSTR lpFileName
# );
#
def LoadLibrary(dll):
    _LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
    _LoadLibraryA.argtypes = [LPSTR]
    _LoadLibraryA.restype = HMODULE
    _LoadLibraryA.errcheck = RaiseIfZero
    return _LoadLibraryA(dll)


DELTA_FLAG_TYPE = ctypes.c_ulonglong
DELTA_FILE_TYPE = ctypes.c_ulonglong
DELTA_FLAG_NONE = 0
DELTA_APPLY_FLAG_ALLOW_PA19 = 1

DELTA_MAX_HASH_SIZE = 32


class DELTA_HASH(ctypes.Structure):
    _fields_ = [
        ("HashSize", DWORD),
        ("HashValue", BYTE * DELTA_MAX_HASH_SIZE)
    ]


class DELTA_HEADER_INFO(ctypes.Structure):
    _fields_ = [
        ("FileTypeSet", DELTA_FILE_TYPE),
        ("FileType", DELTA_FILE_TYPE),
        ("Flags", DELTA_FILE_TYPE),
        ("TargetSize", SIZE_T),
        ("TargetFileTime", FILETIME),
        ("TargetHashAlgId", ALG_ID),
        ("TargetHash", DELTA_HASH),
    ]

    def __str__(self):
        return '\n'.join([
            "[+] FileTypeSet     : 0x{0:X}".format(self.FileTypeSet),
            "[+] FileType        : 0x{0:X}".format(self.FileType),
            "[+] Flags           : 0x{0:X}".format(self.Flags),
            "[+] TargetSize      : 0x{0:X}".format(self.TargetSize),
            "[+] TargetFileTime  : {0}".format(str(self.TargetFileTime)),
            "[+] TargetHashAlgId : 0x{0:X}".format(self.TargetHashAlgId),
            "[+] TargetHash      : {0}".format(
                "".join("{0:02X}".format(x) for x in self.TargetHash.HashValue[:self.TargetHash.HashSize])),
        ])


class DELTA_INPUT(ctypes.Structure):
    _fields_ = [
        ("lpStart", LPBUFFER),
        ("uSize", ULONG),
        ("Editable", BOOL)]


class DELTA_OUTPUT(ctypes.Structure):
    _fields_ = [
        ("lpStart", LPBUFFER),
        ("uSize", ULONG)]


#
# BOOL  WINAPI  ApplyDeltaB(
#    DELTA_FLAG_TYPE  ApplyFlags,
#    DELTA_INPUT      Source,
#    c      Delta,
#    LPDELTA_OUTPUT   lpTarget
#   );
#
def ApplyDeltaB(source, delta, flags=DELTA_APPLY_FLAG_ALLOW_PA19):
    _ApplyDeltaB = ctypes.windll.msdelta.ApplyDeltaB
    _ApplyDeltaB.argtypes = [DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT, ctypes.POINTER(DELTA_OUTPUT)]
    _ApplyDeltaB.restype = BOOL
    _ApplyDeltaB.errcheck = RaiseIfZero
    dsource = DELTA_INPUT()
    dsource.lpStart = ctypes.create_string_buffer(source)
    dsource.uSize = len(source)
    dsource.Editable = False
    ddelta = DELTA_INPUT()
    ddelta.lpStart = ctypes.create_string_buffer(delta)
    ddelta.uSize = len(delta)
    ddelta.Editable = False
    out = DELTA_OUTPUT()
    _ApplyDeltaB(flags, dsource, ddelta, ctypes.byref(out))
    return out


#
# BOOL  WINAPI  GetDeltaInfoA(
#    LPCSTR               lpDeltaName,
#    LPDELTA_HEADER_INFO  lpHeaderInfo
#    );
#
# Note: This doesn't work with file distributed inside KB as there is a
# checksum at the start of the file
# msdelta!compo::CheckBuffersIdentityFactory::CheckBuffersIdentityComponent::InternalProcess+0x84:
# 00007ffe`8d4d6894 e8aa5b0300      call    msdelta!memcmp (00007ffe`8d50c443)
#
def GetDeltaInfo(delta):
    _GetDeltaInfoA = ctypes.windll.msdelta.GetDeltaInfoA
    _GetDeltaInfoA.argtypes = [LPCSTR, ctypes.POINTER(DELTA_HEADER_INFO)]
    _GetDeltaInfoA.restype = BOOL
    _GetDeltaInfoA.errcheck = RaiseIfZero
    info = DELTA_HEADER_INFO()
    _GetDeltaInfoA(delta, ctypes.byref(info))
    return info


#
# BOOL  WINAPI  GetDeltaInfoB(
#     DELTA_INPUT          Delta,
#     LPDELTA_HEADER_INFO  lpHeaderInfo
#     );
#
def GetDeltaInfoB(source):
    _GetDeltaInfoB = ctypes.windll.msdelta.GetDeltaInfoB
    _GetDeltaInfoB.argtypes = [DELTA_INPUT, ctypes.POINTER(DELTA_HEADER_INFO)]
    _GetDeltaInfoB.restype = BOOL
    _GetDeltaInfoB.errcheck = RaiseIfZero
    input = DELTA_INPUT()
    input.lpStart = ctypes.create_string_buffer(source)
    input.uSize = len(source)
    input.Editable = False
    info = DELTA_HEADER_INFO()
    _GetDeltaInfoB(input, ctypes.byref(info))
    return info


def get_delta_info(source):
    buf = open(source, "rb").read()
    buf = buf[4:]  # remove CRC
    x = GetDeltaInfoB(buf)
    return x


def apply_delta(source, delta, outfile):
    bufs = open(source, "rb").read()
    bufd = open(delta, "rb").read()
    bufd = bufd[4:]  # remove CRC
    out = ApplyDeltaB(bufs, bufd)
    open(outfile, "wb").write(out.lpStart[:out.uSize])



class DeltaPatch:
    def __init__(self):
        self.name = 'Delta'
        self.description = 'Delta Patching for Windows'
        self.author = "R3zk0n"
        self.version = "1.0"

    def extract_cab(self, file):
        pass

    def extract_msu(self, file):
        pass

    def extract_msp(self, file, arg, delta=None, out=None):
        if arg == "info":
            Lib = LoadLibrary("msdelta.dll")
            get_delta_info(file, Lib=Lib)
        elif arg == "apply":
            apply_delta(file, delta, out)
