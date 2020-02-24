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
#def IPHeader():
import thread, time
import Transport
from generalfunction import GenerateSN,GeneratePacketHeader,Confirm

#1.2.28 huo qu vlan lie biao 
class CGetVlanList():
    def __init__(self,id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 55
        self.param = 0
        self.lino = parameters[0]#data[0]-save link No

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.param,self.lino)
        struct.pack_into('!B',buf,262,self.flag)
        return  buf.raw
    def PackPacket(self):
        
        #sn = GenerateSN()
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

        content_receive_general_resp = unpack('!BBB' , packet_receive[156:159])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        vlannum = content_receive_general_resp[2]
        print vlannum
        if Status == 0:
            existrecords = DVlanList.query.filter_by(id=self.id,lino=self.lino).all()
            existlen = len(existrecords)
            if vlannum == 0:
               for record in existrecords:
                   db.session.delete(record)
            else:
                for index in range(vlannum):
                    content_receive_data_pack = packet_receive[160+24*index:184+24*index]
                    content_receive_data = unpack('!L4s4s4s4sBBBB',content_receive_data_pack)
                    vid = content_receive_data[0]#vlan ID
                    if vid == 0:
                       break
                    subnet = socket.inet_ntoa(content_receive_data[1])#subnet address
                    netmask = socket.inet_ntoa(content_receive_data[2])#netmask
                    forward_next_hop = socket.inet_ntoa(content_receive_data[3])#router address
                    backward_next_hop = socket.inet_ntoa(content_receive_data[4])#switch address
                    dev_in_this_vlan = bool(content_receive_data[5])#whether device belongs to this vlan 1-yes 0-no
                    lino = content_receive_data[6]#lineno 0-first link 1-second link
                    if lino not in [0,1]:
                        continue
                    is_apply_arp = bool(content_receive_data[7])#whether enable ARP 1-enable 0-close
                    if index < existlen:
                        record = existrecords[index]
                        record.vid = vid
                        record.subnet = subnet
                        record.netmask = netmask
                        record.forward_next_hop = forward_next_hop
                        record.backward_next_hop = backward_next_hop
                        record.dev_in_this_vlan = dev_in_this_vlan
                        record.lino = lino
                        record.is_apply_arp = is_apply_arp
                        db.session.add(record)              
                    else:  
                        newrecord =  DVlanList(self.id, lino,vid,subnet,netmask,forward_next_hop,backward_next_hop,dev_in_this_vlan,is_apply_arp) 
                        print newrecord
                        db.session.add(newrecord) ### add the newrecord to the database
                        db.session.commit()
                for i in range(vlannum,existlen):
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

#1.2.29 tian jia vlan 
class CAddVlan():
    def __init__(self, id,dest_host, parameters, target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 56
        self.Param = 0
        self.vid = parameters[0]
        self.subnet = socket.inet_aton(parameters[1])[-1::-1]
        self.netmask = socket.inet_aton(parameters[2])[-1::-1]
        self.forward_next_hop = socket.inet_aton(parameters[3])[-1::-1]
        self.backward_next_hop = socket.inet_aton(parameters[4])[-1::-1]
        self.dev_in_this_vlan = parameters[5]
        self.lino = parameters[6]
        self.is_apply_arp = parameters[7]

        self.dbsubnet = parameters[1]
        self.dbnetmask = parameters[2]
        self.dbforward = parameters[3]
        self.dbbackward = parameters[4]
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.Param)
        struct.pack_into('L',buf,6,self.vid)
        struct.pack_into('4s4s4s4sBBB',buf, 10, self.subnet,self.netmask,self.forward_next_hop,self.backward_next_hop,self.dev_in_this_vlan,self.lino, self.is_apply_arp)
        struct.pack_into('!B',buf,262, self.flag)
        return  buf.raw
    def PackPacket(self):
        
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def  ParsePacket(self, packet_receive):
        
        if len(packet_receive) < 156:   ##change the size according the packet
            return None 
        
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

#1.2.30 shan chu vlan 
class CDeleteVlan():
    def __init__(self, id,dest_host, parameters, target    ):           
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        self.lino = parameters[1]
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 57
        self.Param = 0
        self.vid = parameters[0]#0-3 bytes:vid

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.Param)
        struct.pack_into('L',buf, 6, self.vid)
        struct.pack_into('!B',buf,128,self.flag)
        
        return  buf.raw
    def PackPacket(self):
        
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def  ParsePacket(self, packet_receive):
        
        if len(packet_receive) < 156:   ##change the size according the packet
            return None 
        
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
        if Status == 0:
            record = DVlanList.query.filter_by(id=self.id,lino=self.lino,vid=self.vid).first()
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

#1.2.61            
class CSetMultiIP():
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 104
        self.multi_ip = parameters[0]
        self.lino = parameters[1]

        self.flag = 128 #0x80


    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.multi_ip,self.lino)
        struct.pack_into('!B',buf,262,self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirmh
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
            record = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id,lino=self.lino).first()
            if record == None:
                dict = {'multi_ip':bool(self.multi_ip)}
                newrecord = DPrivateEquipmentLinkInfo(self.id,0,dict)
                db.session.add(newrecord)
            else:
                record.multi_ip = bool(self.multi_ip)
            db.session.commit()              
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
            