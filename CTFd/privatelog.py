#!/usr/bin/env python
# coding=utf-8
from flask.ext.sqlalchemy import SQLAlchemy

from CTFd import models
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from struct import *
from time import ctime,sleep
from os import system
from CTFd.models import *
import socket
import struct
import ctypes
import datetime
import thread, time
import Transport
from generalfunction import GenerateSN,GeneratePacketHeader,Confirm

#1.2.23 shanchurizhi 
class CDeleteLog():
    def __init__(self, id,dest_host, target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1
        self.Command_Code = 42

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code, self.flag)
        
        return  buf.raw
    def PackPacket(self):
        
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh
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
            records = models.DMachineLog.query.filter_by(id=self.id).all()
            for record in records:
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

#1.2.50
class CGetLogServerInfo():
    def __init__(self, id,dest_host, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 
        self.Command_Code = 92

        self.flag = 128 #0x80

    def PackContent(self): 
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!B',buf,262,self.flag)
        return  buf.raw
    
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh
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
        content_receive_head_pack = packet_receive[152:156]
        content_receive_head = unpack('!BBH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BBBB' , packet_receive[156:160])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        servernums = content_receive_general_resp[2]
        if Status == 0:
            existrecords = DLogServerInfo.query.filter_by(id=self.id).all()
            existlen = len(existrecords)             
            for index in range(servernums):
                syslog_messagec = packet_receive[160 + 32 * index : 192 + 32 * index]
                content_receive_data = unpack('!20s6sBBL', syslog_messagec)
                ipaddr = content_receive_data[0].strip('\x00').split('\x00')[0] #the ip of sys_log
                if ipaddr != "":
                    ports = int(content_receive_data[1].strip('\x00').split('\x00')[0])#the PortNum
                    direction_dict = ['外网','内网']
                    try:
                        direction = direction_dict[content_receive_data[2]] #direction
                    except:
                        direction = "未知"
                    lino = content_receive_data[3] #Link Number
                    vlan_id = content_receive_data[4] #vlan id
                    if index < existlen:
                        record = existrecords[index]
                        record.serverid = index + 1
                        record.ipaddr = ipaddr
                        record.ports = ports
                        record.direction = direction
                        record.lino = lino
                        record.vlan_id = vlan_id
                        db.session.add(record)
                    else:
                        newrecord = DLogServerInfo(self.id,index + 1,ipaddr,ports,direction,lino,vlan_id) # Create a new record, the DataBaseName is given by yourselves
                        db.session.add(newrecord) ### add the newrecord to the database
                else:
                    servernums = 0
            for i in range(servernums,existlen):
                db.session.delete(existrecords[i]) 
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

# 1.2.51            
class CAddLogServer():
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 36 #parameter1 the length of data
        self.Command_Code = 93
        self.ipaddr = parameters[0] #the ip of log_server
        self.ports = parameters[1] #the port Number
        self.direction = parameters[2] #direction
        self.line = parameters[3] #the link number
        self.vlanid = parameters[4] #vlan id 

        self.flag = 128 #0x80

    def PackContent(self):
        buf = ctypes.create_string_buffer(48)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!'+str(len(self.ipaddr))+'s',buf,8,self.ipaddr)
        port = (self.ports + '\x00' * 6)[:6]
        struct.pack_into('6s',buf,28, port)
        struct.pack_into('!BBLB',buf,34,self.direction,self.line,self.vlanid,self.flag)
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh
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

#1.2.52
class CDeleteLogServer():
    def __init__(self, id,dest_host, parameters, target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 9
        self.Command_Code = 94
        self.syslogno = parameters[0] #the numberID of the log_server

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!BB',buf,8,self.syslogno,self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
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

        content_receive_head_pack = packet_receive[152:156]
        content_receive_head = unpack('!BBH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        #Param = content_receive_head_pack[]
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
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