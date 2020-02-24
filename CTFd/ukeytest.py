import ctypes
ll = ctypes.cdll.LoadLibrary
ctypes.CDLL("./lib/libecc.so",ctypes.RTLD_GLOBAL)
ctypes.CDLL("./lib/libhsskf.so",mode=ctypes.RTLD_GLOBAL)
lib = ll("./usbkey.so")
buf = ctypes.create_string_buffer(64)
buf2 = ctypes.create_string_buffer(16)
buf3 = ctypes.create_string_buffer(32)
buf4 = ctypes.create_string_buffer(32)
i2 = ctypes.c_int()
i = ctypes.c_int()
s = lib.use_ukey_prepare()
p=lib.get_ukey_id(buf,ctypes.pointer(i))
print "info = ",p
r = lib.ukey_init(buf,ctypes.pointer(i))
print "r = ",r
