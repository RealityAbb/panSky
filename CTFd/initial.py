#!/usr/bin/env python
# coding=utf-8
from flask.ext.sqlalchemy import SQLAlchemy

from CTFd.models import db, LMRoute, DLeadMachineCert,Certificates
#from CTFd import models
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from struct import *
from time import ctime,sleep
from os import system
from flask import current_app as app
import os
import socket
import struct
import ctypes
import datetime
#def IPHeader():
import thread, time
import Transport
from generalfunction import GenerateSN,GeneratePacketHeader,Confirm

def LMGeneratePacketHeader(target = 0):
    buf = ctypes.create_string_buffer(128)
    struct.pack_into('B',buf,5,target)
    return buf.raw
	
#class Hello():

class CGenerateDeviceCert():
    def __init__(self, parameters, target = 0):
        
        self.sn = GenerateSN()
        self.target = target
        self.FunCode = 253
        self.Param1 = 253  
        self.Param2 = 268
        self.Command_Code = 3
        self.reserved = 0  
        self.serial = 0 
        self.country = parameters[0]  
        self.province = parameters[1]
        self.city = parameters[2]
        self.organ = parameters[3]
        self.depart = parameters[4]
        self.name = parameters[5]
        self.email = parameters[6] 

        self.flag = 128
    def PackContent(self):
        buf = ctypes.create_string_buffer(288)
        country = (self.country + '\x00' * 4)[:4]
        province = (self.province + '\x00' * 32)[:32]
        city = (self.city + '\x00' * 32)[:32]
        organ = (self.organ + '\x00' * 64)[:64]
        depart = (self.depart + '\x00' * 32)[:32]
        name = (self.name + '\x00' * 32)[:32]
        email = (self.email + '\x00' * 64)[:64]
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code)
        struct.pack_into('!L4s32s',buf,8, self.serial, country, province)
        struct.pack_into('32s64s32s32s', buf, 48, city, organ, depart, name)
        struct.pack_into('64s',buf,208, email)
        struct.pack_into('B',buf, 272, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        print 'self.sn = ', self.sn
        print 'sn = ', sn
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != 253:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        return  Status
    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, '0.0.0.0', self.sn)
        if packet_receive == None:
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status
class ExportCert():
    def __init__(self, target = 0):
        self.dest_host = "0.0.0.0"
        self.target = target
        self.sn = GenerateSN()
        self.FunCode = 253
        self.Param1 = 253
        self.Param2 = 1
        self.Command_Code = 21

        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != 253:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        print Length
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        print Return_Code
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        if Status == 0:

            content_receive_data_length = unpack('!H',packet_receive[162:164])[0]

            s = str(content_receive_data_length) + 's'
            content_receive_data_pack = packet_receive[164 : 164 + content_receive_data_length]
            content_receive_data = unpack(s,content_receive_data_pack)[0]
            print repr(content_receive_data)
            path = os.path.join(app.config['CERTIFICATE_FOLDER'], 'premachine.tar.gz')
            with open(path,"w") as f:
                f.write((content_receive_data))
        return  Status
    def  SendAndRecieve(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status
class InitialUkey():
    def __init__(self,parameters,target = 0):
        self.dest_host = '0.0.0.0'
        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 253
        self.Param1 = 253  #parameters 1
        self.Param2 = 332
        self.Command_Code = 110
        self.reserved = 0  #unsigned char reserved[3]
        self.pk = parameters[7]
        self.serial = 0 
        self.country = parameters[0]  #channelnumber
        self.province = parameters[1]
        self.city = parameters[2]
        self.organ = parameters[3]
        self.depart = parameters[4]
        self.name = parameters[5]
        self.email = parameters[6]

        self.flag = 128  # 0x80

        self.id = parameters[8].split("\x00")[0]
    def PackContent(self):
        buf = ctypes.create_string_buffer(352)
        country = (self.country + '\x00' * 4)[:4]
        province = (self.province + '\x00' * 32)[:32]
        city = (self.city + '\x00' * 32)[:32]
        organ = (self.organ + '\x00' * 64)[:64]
        depart = (self.depart + '\x00' * 32)[:32]
        name = (self.name + '\x00' * 32)[:32]
        email = (self.email + '\x00' * 64)[:64]
        pk = (self.pk + '\x00' * 64)[:64]
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code)
        struct.pack_into('64s',buf,8,pk)
        struct.pack_into('!L4s32s',buf,72, self.serial, country, province)
        struct.pack_into('32s64s32s32s', buf, 112, city, organ, depart, name)
        struct.pack_into('64s',buf,272, email)
        struct.pack_into('B',buf, 336, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != 253:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        if Status == 0:
            content_receive_data_length = unpack('i',packet_receive[162:166])[0]
            s = str(content_receive_data_length) + 's'
            content_receive_data_pack = packet_receive[166 : 166 + content_receive_data_length]
            content_receive_data = unpack(s,content_receive_data_pack)[0]

            path = os.path.join(app.config['CERTIFICATE_FOLDER'], self.id + '.pem')
            with open(path,"w") as f:
                f.write((content_receive_data))
        return Status
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status
class ExportUKeyResp():
    def __init__(self, target = 1):
        self.dest_host = "0.0.0.0"
        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 253
        self.Param1 = 253  #parameters 1
        self.Param2 = 1
        self.Command_Code = 53

        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        #Receive()
        if len(packet_receive) < 156:
            return None       
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != 253:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        if Status == 0:

            content_receive_data_length = unpack('!H',packet_receive[162:164])[0]

            s = str(content_receive_data_length) + 's'
            content_receive_data_pack = packet_receive[164 : 164 + content_receive_data_length]
            content_receive_data = unpack(s,content_receive_data_pack)[0]

            with open('static/uploads/usbkey.der',"w") as f:
                f.write((content_receive_data))
        return  Status
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status
class ConfigPredeviceIP():
    def __init__(self, parameters, target = 0):
        self.dest_host = "0.0.0.0"
        self.target = 1
        self.sn = GenerateSN()
        # the 
        self.FunCode = 253
        self.Param1 = 253  #parameters 1
        self.Param2 = 44    #Length
        self.Command_Code = 106  
        self.reserved = 0 
        self.ipaddr1 = socket.inet_aton(parameters[0])
        self.ipmask1 = socket.inet_aton(parameters[1])
        self.ipaddr2 = socket.inet_aton(parameters[2])
        self.ipmask2 = socket.inet_aton(parameters[3])
        self.ipaddr3 = socket.inet_aton(parameters[4])
        self.ipmask3 = socket.inet_aton(parameters[5])
        self.ipaddr4 = socket.inet_aton(parameters[6])
        self.ipmask4 = socket.inet_aton(parameters[7])
        self.ipaddr5 = socket.inet_aton(parameters[8])
        self.ipmask5 = socket.inet_aton(parameters[9])  
        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(64)
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code)
        struct.pack_into('4s4s4s4s4s4s4s4s4s4sB', buf, 8, self.ipaddr1,self.ipmask1, self.ipaddr2,self.ipmask2, self.ipaddr3,self.ipmask3, self.ipaddr4,self.ipmask4, self.ipaddr5,self.ipmask5, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        return  Status
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn, 6)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status

class ConfigPredeviceRoute():
    def __init__(self, parameters, target = 0):
        self.dest_host = "0.0.0.0"
        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 253
        self.Param1 = 253  #parameters 1
        self.Param2 = 99    #Length
        self.Command_Code = 107
        self.operation = parameters[0]
        self.keyword = parameters[1] 
        self.IPAddr = parameters[2]
        self.Mask = parameters[3]
        self.Gateway = parameters[4]
        self.interface = parameters[5]

        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(112)
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.operation,self.keyword)
        struct.pack_into('!'+ str(len(self.IPAddr))+'s', buf, 7, self.IPAddr)
        struct.pack_into('!'+ str(len(self.Mask)) + 's', buf, 39, self.Mask)
        struct.pack_into('!'+ str(len(self.Gateway)) + 's', buf, 71, self.Gateway)
        struct.pack_into('B',buf,103,self.interface)
        struct.pack_into('!B',buf, 104, self.flag)

        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        print 'Status = ',Status
        return  Status
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status

class QueryPredeviceIP():
    def __init__(self,target = 0):
        self.dest_host = '0.0.0.0'
        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 253
        self.Param1 = 253  #parameters 1
        self.Param2 = 1    #Length
        self.Command_Code = 108

        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None
 

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]

        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        ips = unpack('4s4s4s4s4s4s4s4s4s4s',packet_receive[162:202])

        ipaddr1 = socket.inet_ntoa(ips[0])
        ipmask1 = socket.inet_ntoa(ips[1])
        ipaddr2 = socket.inet_ntoa(ips[2])
        ipmask2 = socket.inet_ntoa(ips[3])
        ipaddr3 = socket.inet_ntoa(ips[4])
        ipmask3 = socket.inet_ntoa(ips[5])
        ipaddr4 = socket.inet_ntoa(ips[6])
        ipmask4 = socket.inet_ntoa(ips[7])
        ipaddr5 = socket.inet_ntoa(ips[8])
        ipmask5 = socket.inet_ntoa(ips[9])
        return  [Status,[ipaddr1,ipaddr2,ipaddr3,ipaddr4,ipaddr5],[ipmask1,ipmask2,ipmask3,ipmask4,ipmask5]]
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2,[],[]]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1,[],[]]
        else:
            return status

class QueryPredeviceRoute():
    def __init__(self, target = 1):
        self.dest_host = "0.0.0.0"
        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 253
        self.Param1 = 253  #parameters 1
        self.Param2 = 1    #Length
        self.Command_Code = 109

        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):
        #Receive()
        if len(packet_receive) < 254:
            return None       
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]

        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        
        if Status == 0:
            routes = LMRoute.query.all()
            for route in routes:
                db.session.delete(route)
            db.session.commit()
            route_num = unpack('i',packet_receive[162:166])[0]
            route_table = packet_receive[166 : 166 + route_num * 60]
            for index in range(route_num):
                route_receive_pack = route_table[60 * index : 60 + 60 * index]
                route_receive = unpack('i16s16s16s8s', route_receive_pack)
                route_ipaddr = route_receive[1].strip('\x00').split('\x00')[0]
                netmask = route_receive[2].strip('\x00').split('\x00')[0]
                gateway = route_receive[3].strip('\x00').split('\x00')[0]
                type_dict = ["网络路由","主机路由","默认路由"]
                try:
                    routetype = type_dict[route_receive[0]]
                except:
                    routetype = "未知"
                interface = route_receive[4].strip('\x00').split('\x00')[0]
                newrecord = LMRoute(route_ipaddr, netmask, gateway,routetype,interface)
                db.session.add(newrecord)
            db.session.commit()
        return  Status
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status

class CImportCert():
    def __init__(self, parameters,target = 1):   

        self.dest_host = "0.0.0.0"
        self.sn = GenerateSN()
        self.target = target
        self.FunCode = 253
        self.Param1 = 253
        self.Param2 = 2037 
        self.Command_Code = 4            
        self.Cert_Type = parameters[0]    
        self.Peer_Ip = (parameters[1] + '\x00' * 32)[:32]     
        self.Cert_Format = parameters[2]  
        self.Cert_Length = parameters[3]  
        self.Cert_Content = parameters[4] 
        self.flag = 128

    def PackContent(self):
        buf = ctypes.create_string_buffer(2048)   ###change the size
        Cert_Content = (self.Cert_Content + '\x00' * 2000)[:2000]
        struct.pack_into('!BBHBB32sB', buf, 0, self.FunCode,self.Param1, self.Param2,self.Command_Code, self.Cert_Type, self.Peer_Ip, self.Cert_Format)
        struct.pack_into('H2000sB', buf, 39, self.Cert_Length, Cert_Content ,self.flag)
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send
    def ParsePacket(self, packet_receive):
        
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        if Return_Code != self.Command_Code + 1:
            return None
        Status = content_receive_data_head[1]
        return  Status
    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status
#1.2.7 shan chu zheng shu
class CDeleteCert():
    def __init__(self, parameters,  target = 1   ):   

        self.id = id
        self.dest_host = "0.0.0.0"
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 253
        self.Param1 = 253
        self.Param2 = 33 #data lenth

        self.Command_Code = 12      #uchar
        self.IpAddr = parameters[0]  #uchar[32], cert ip address

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(48)   ###change the size 
        IpAddr = (self.IpAddr + '\x00' * 32)[:32].encode('utf-8')
        print self.IpAddr,"&&&&&&&&&&&&&&&&&"
        print type(IpAddr)
        content = struct.pack_into('!BBHB32sB', buf, 0, self.FunCode, self.Param1, self.Param2, \
            self.Command_Code, IpAddr, self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def ParsePacket(self, packet_receive):

        print repr(packet_receive)


        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None
        content_receive_head_pack = packet_receive[152:156]
        content_receive_head = unpack('!BBH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            record = DPrivateCertInfo.query.filter_by(id=self.id, cert_name=self.IpAddr).first()
            if record != None:
                db.session.delete(record)
                db.session.commit()
        return Status
        

    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status

class CRestartMachine():
    def __init__(self,target = 1):

        self.dest_host = '0.0.0.0'
        self.sn = GenerateSN()
        self.target = target
        
        self.FunCode = 253
        self.Param1 = 253  
        self.Param2 = 1    
        self.Command_Code = 24

        self.flag = 128
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirm = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirm
        return packet_send

    def  ParsePacket(self, packet_receive):

        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
        Status = content_receive_data_head[1]
        return  Status

    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn,6)
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status
class CQueryCertList():
    def __init__(self,target = 0):   
    
        self.id = id
        self.dest_host = "0.0.0.0"
        self.target = target
        self.sn = GenerateSN()
        
        self.FunCode = 253
        self.Param1 = 253
        self.Param2 = 2

        self.Command_Code = 5  
        self.Cert_Type = 6     

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   
        content = struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, \
            self.Command_Code, self.Cert_Type, self.flag)
        
        return  buf.raw

    def PackPacket(self):
        
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        
        packet_send =  snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None
     

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
       
        Status = content_receive_data_head[1]

        Cert_Number = unpack('!L',packet_receive[162:166])[0]             
        if Status == 0:                          
            existrecords = Certificates.query.filter_by(id=self.id).all()
            dict = {}
            for existrecord in existrecords:
                dict.update({existrecord.cert_name:existrecord})
            existrecordlist = dict.keys()
            

            for i in range(Cert_Number):
                cert_list_receive_pack = packet_receive[166 + 30 * i : 196 + 30 * i]
                cert_list_receive = unpack('!30s', cert_list_receive_pack)
                Cert_FileName = cert_list_receive[0].strip('\x00').split('\x00') [0] 
                Cert_Type = 5
                
                if Cert_FileName.find('DMS') != -1:
                    Cert_Type = 1
                else:
                    Cert_Type = 5
                
                if Cert_FileName not in existrecordlist:
                    newrecord = Certificates(Cert_FileName)
                    db.session.add(newrecord)
                else:
                    existrecordlist.remove(Cert_FileName)
            for cert_name in existrecordlist:
                db.session.delete(dict[cert_name])
            db.session.commit()
        return Status
        

    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: 
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status

class CGetCertPK():
    def __init__(self,parameters,target = 0):   
       
        self.id = id
        self.dest_host = "0.0.0.0"
        self.target = target
        
        self.sn = GenerateSN()
        
        self.FunCode = 253
        self.Param1 = 253
        self.Param2 = 2008

        self.Command_Code = 111  
        self.reserved = 0  
        self.Cert_length = parameters[0]
        self.Cert_Content = parameters[1]

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(2016)   
        
        struct.pack_into('!BBH',buf,0,self.FunCode,self.Param1,self.Param2)
        struct.pack_into('!B',buf,4,self.Command_Code)
        struct.pack_into('L',buf,8,self.Cert_length)
        struct.pack_into(str(self.Cert_length) + 's', buf,12,self.Cert_Content)
        struct.pack_into('B',buf,2012,self.flag)
        return  buf.raw

    def PackPacket(self):
       
        snh = struct.pack("!L", self.sn)
        PacketHeader = LMGeneratePacketHeader(self.target)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        
        packet_send =  snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None
     

        content_receive_pack = packet_receive[152:156]
        content_receive = unpack('BBH' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]        
        Length = content_receive[2] - 2
        content_receive_data_head_pack = packet_receive[158:162]
        content_receive_data_head = unpack('!BBH',content_receive_data_head_pack)
        Return_Code = content_receive_data_head[0]
       
        Status = content_receive_data_head[1]
        pk = ""
        if Status == 0:
            pk = unpack('64s',packet_receive[162:162+64])[0]
            print 'pk = ',pk,"*&&*&*&*&*&*&*&*&*&*&*&&"
        return [Status,pk]
        

    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2,""]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1,""]
        else:
            return status
            
