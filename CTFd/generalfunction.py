#!/usr/bin/env python
# coding=utf-8
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from struct import *
from os import system

import socket
import struct
import ctypes
import datetime
import thread

lock_sn = thread.allocate_lock()

SN = 0

def GenerateSN():
    global SN, lock_sn
    try:
        lock_sn.acquire()
        if SN == 2**31 -1:
            SN = 0
        else:
            SN = SN + 1
        lock_sn.release()
    except:
        try:
            lock_sn.release()
        except:
            pass
    return SN

def GeneratePacketHeader(target, dest_host):
    caddr = socket.inet_aton( dest_host)
    buf = ctypes.create_string_buffer(128)
    struct.pack_into('!B4sB',buf,0,1,caddr,target)
    # if target == 0:
    #     struct.pack_into('!B', buf, 0, target)
    # else: 
    #     status = struct.pack_into('!B4s', buf, 0, 1, caddr)
    return buf.raw
def Confirm():
    buf = ctypes.create_string_buffer(64) 
    return buf.raw

def SwitchErrorCode(code):
    dict = {1: '不存在该隧道',\
        2: '该隧道已存在',\
        3: '签名验证失败', \
        6: '解密出的明文数据不合法',\
        7: '该项操作当前被禁止',\
        8: '获取加密统计数据失败',\
        10: '添加隧道安全策略时失败',\
        11: '删除隧道安全策略时失败',\
        12: '重置装置失败',\
        13: '重置隧道失败',\
        14: '获取日志文件长度失败',\
        15: '读取日志文件失败',\
        17: '操作冲突',\
        -2: '请求超时',\
        -1: '返回数据包错误',\
        -3: '输入信息有误',\
        0: '操作成功'}
    if code in dict.keys():
        return dict[code]
    else:
        return '错误码：' + str(code)

def SwitchErrorCode2(code):
    dict = {1:'操作失败！',\
            0:'操作成功！'}
    if code in dict.keys():
        return dict[code]
    else:
        return '错误码：' + str(code)
