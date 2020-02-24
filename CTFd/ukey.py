import ctypes
ll = ctypes.cdll.LoadLibrary
ctypes.CDLL("./CTFd/lib/libecc.so",mode=ctypes.RTLD_GLOBAL)
ctypes.CDLL("./CTFd/lib/libhsskf.so",mode=ctypes.RTLD_GLOBAL)
lib = ll("./CTFd/usbkey.so")


def m_ukey_prepare():
	s = lib.use_ukey_prepare()
	return s

def m_ukey_get_info():
    id_ptr = ctypes.create_string_buffer(32)
    id_len_ptr = ctypes.c_int()
    r = lib.get_ukey_id(id_ptr,ctypes.pointer(id_len_ptr))
    return {"r":r,"id_ptr":id_ptr.raw,'id_len':id_len_ptr.value}

def m_ukey_init(username, pwd):
    username_str = ctypes.create_string_buffer(30)
    username_str.value = username;
    username_ptr = ctypes.pointer(username_str)
    pwd_str = ctypes.create_string_buffer(16)
    pwd_str.value = pwd;
    pwd_ptr = ctypes.pointer(pwd_str)
    id_ptr = ctypes.create_string_buffer(32)
    id_len_ptr = ctypes.c_int()
    pk_ptr = ctypes.create_string_buffer(64)
    pk_len_ptr = ctypes.c_int()
    r = lib.ukey_init(username_ptr, pwd_ptr, id_ptr, ctypes.pointer(id_len_ptr), pk_ptr, ctypes.pointer(pk_len_ptr))
    return {"r":r,"id_ptr":id_ptr.raw,'id_len':id_len_ptr.value,"pk_ptr":pk_ptr.raw,'pk_len':pk_len_ptr.value}

def m_ukey_authenticate(username, pwd, id, pk, pk_len):
    username_str = ctypes.create_string_buffer(30)
    username_str.value = username;
    username_ptr = ctypes.pointer(username_str)

    pwd_str = ctypes.create_string_buffer(16)
    pwd_str.value = pwd;
    pwd_ptr = ctypes.pointer(pwd_str)

    id_str = ctypes.create_string_buffer(32)
    id_str.value = id;
    id_ptr = ctypes.pointer(id_str)

    pk_str = ctypes.create_string_buffer(64)
    pk_str.value = pk;
    pk_ptr = ctypes.pointer(pk_str)

    pk_len_str = ctypes.c_int()
    pk_len_str.value = pk_len;
    r = lib.ukey_authenticate(username_ptr, pwd_ptr, id_ptr, pk_ptr, ctypes.pointer(pk_len_str))
    return r

def m_ukey_cycle_check(id):
    id_str = ctypes.create_string_buffer(32)
    id_str.value = id
    id_ptr = ctypes.pointer(id_str)
    return lib.ukey_cycle_check(id_ptr)

def m_modify_ukey_pwd(id, oldpwd, newpwd):
    id_str = ctypes.create_string_buffer(32)
    id_str.value = id
    id_ptr = ctypes.pointer(id_str)
    oldpwd_str = ctypes.create_string_buffer(32)
    oldpwd_str.value = oldpwd
    oldpwd_ptr = ctypes.pointer(oldpwd_str)
    newpwd_str = ctypes.create_string_buffer(32)
    newpwd_str.value = newpwd
    newpwd_ptr = ctypes.pointer(newpwd_str)
    return lib.modify_ukey_pwd(id_ptr, oldpwd_ptr, newpwd_ptr)