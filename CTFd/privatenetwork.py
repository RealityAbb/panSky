#!/usr/bin/env python
# coding=utf-8
from flask_sqlalchemy import SQLAlchemy

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

#1.2.13 pei zhi lu you biao
class CSetRoute():
    def __init__(self, id,dest_host, parameters,  target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 99 #data lenth

        self.Command_Code = 25      #uchar
        self.keyword = parameters[0] #uchar, type: 0-net, 1-host, 2-default
        self.IP_Addr = parameters[1] #uchar[32]
        self.Mask = parameters[2]    #uchar[32]
        self.Gateway = parameters[3] #uchar[32]
        self.lino = parameters[4]  #uchar
        self.flag = 128

    def PackContent(self):
        buf = ctypes.create_string_buffer(112)   ###change the size
        IP_Addr = (self.IP_Addr + '\x00' * 32)[:32]
        Mask = (self.Mask + '\x00' * 32)[:32]
        Gateway = (self.Gateway + '\x00' * 32)[:32]
        content = struct.pack_into('!BBHBB32s32s32sBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.keyword, IP_Addr, Mask, Gateway,self.lino, self.flag)
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        #Packet = IPHeader + snh + PacketHeader + PacketContent + confirmh
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

        content_receive_head_pack = packet_receive[152:160]
        content_receive_head = unpack('!BBHBB2s', content_receive_head_pack)
        FunCode = content_receive_head[0]
        Param = content_receive_head[1]         #P=S  
        Length = content_receive_head[2]        #L=Data length
        Return_Code = content_receive_head[3]   #uchar
        Status = content_receive_head[4]        #uchar
        reserve = content_receive_head[5]       #uchar[2]        
        if FunCode != self.FunCode:
            return None
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            route_table_receive_pack = packet_receive[160:164]
            route_table_receive = unpack('i', route_table_receive_pack)
            route_num = route_table_receive[0]
            #print "###### route_num ####### = ",route_num
            existrecords = DRouteTable.query.filter_by(id=self.id,lino=self.lino).all()
            existlen = len(existrecords)
            if route_num == 0:
                for i in range(0,existlen):
                    db.session.delete(existrecords[i])
            else:                
                for index in range(route_num):
                    route_receive_pack = packet_receive[164 + 52 * index : 216 + 52 * index]
                    route_receive = unpack('16s16s16si', route_receive_pack)
                    #print route_receive
                    ipaddr = route_receive[0].strip('\x00').split('\x00')[0]
                    netmask = route_receive[1].strip('\x00').split('\x00')[0]
                    gateway = route_receive[2].strip('\x00').split('\x00')[0]
                    #print "###### route_type ###### = ",route_receive[3]
                    type_dict = ["网络路由","主机路由","默认路由"]
                    try:
                        type = type_dict[route_receive[3]]
                    except:
                        type = "未知"
                    if index < existlen:
                        record = existrecords[index]
                        #record.lino = lino
                        record.routenumber = index + 1
                        record.ipaddr = ipaddr
                        record.netmask = netmask
                        record.gateway = gateway
                        record.type = type
                        db.session.add(record)
                    else:
                        #print '#########newrecord'
                        newrecord = DRouteTable(self.id,self.lino,index + 1,ipaddr, netmask, gateway, type)
                        db.session.add(newrecord)
                for i in range(index,existlen):
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

#1.2.14 shan chu lu you biao
class CDeleteRoute():
    def __init__(self, id, dest_host, parameters,  target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 4 #data lenth

        self.Command_Code = 26      #uchar
        self.keyword = parameters[0] #uchar, type of route
        self.Item = parameters[1]    #uchar, id of route
        self.lino = parameters[2]  #uchar, line of route
        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        struct.pack_into('!BBHBBBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code, self.keyword, self.Item, self.lino, self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        #Packet = IPHeader + snh + PacketHeader + PacketContent + confirmh
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

        Param = content_receive_head[1]    
        Length = content_receive_head[2]   

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

#1.2.20 shezhishengchengshuxieyi 
class CSetSTP():
    def __init__(self, id,dest_host,parameters,target    ):   
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 3
        self.Command_Code = 33
        self.stpstat = parameters[0]#1-open 0-close
        self.lino = parameters[1]#link

        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.stpstat,self.lino,self.flag)
        
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

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            record = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id, lino=self.lino).first()
            if record == None:
                dict = {'stp_state':bool(self.stpstat)}
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict) # Create a new record, the DataBaseName is given by yourselves
                db.session.add(newrecord)
            else:
                record.stp_state = bool(self.stpstat)
                db.session.add(record)
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


#1.2.32 huo qu quan ju zhuan fa ce lve
class CGetGlobalForwardPolicy():
    def __init__(self, id,dest_host,  target    ):   
    
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1
        self.Command_Code = 59
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        
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

        content_receive_general_resp = unpack('!BB2s' , packet_receive[156:160])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        reserve = content_receive_general_resp[2]
        strategy = ord(reserve[0])
        strategy_1 = bool((strategy & 0x01))
        strategy_2 = bool((strategy >> 4) & 0x01)
        
        record1 = DPrivateEquipmentLinkInfo.query.filter_by(id = self.id, lino = 0).first()
        record2 = DPrivateEquipmentLinkInfo.query.filter_by(id = self.id, lino = 1).first()
        if record1 == None:
            dict = {'global_forward_policy':strategy_1}
            newrecord = DPrivateEquipmentLinkInfo(self.id, 0, dict)
            db.session.add(newrecord)
        else:
            record1.global_forward_policy = strategy_1
            db.session.add(record1)
        if record2 == None:
            dict = {'global_forward_policy':strategy_2}
            newrecord = DPrivateEquipmentLinkInfo(self.id, 1, dict)
            db.session.add(newrecord)      
        else:
            record2.global_forward_policy = strategy_2
            db.session.add(record2)
        db.session.commit()
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

#1.2.33 she zhi quan ju zhuan fa ce lve
class CSetGlobalForwardPolicy():
    def __init__(self, id,dest_host,parameters, target    ):   

        self.id = id
        self.dest_host = dest_host      
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 60
        self.policy = parameters[0] #int
        self.lino = parameters[1] #lino
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.policy, self.lino)
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

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None

        if Status == 0:
            record = DPrivateEquipmentLinkInfo.query.filter_by(id = self.id, lino=self.lino).first()
            if record == None:
                dict = {'global_forward_policy':bool(self.policy)}
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict)
                db.session.add(newrecord)
            else:
                record.global_forward_policy = bool(self.policy)
                db.session.add(record)
            db.session.commit()
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

###########1.2.34
class CGetAllowedAccessState():
    def __init__(self, id,dest_host,  target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1
        self.Command_Code = 61

        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
        
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

        content_receive_general_resp = unpack('!BBBB' , packet_receive[156:160])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            access_state = content_receive_general_resp[2]
            
            access_state_1 = bool((access_state & 0x01))
            access_state_2 = bool((access_state >> 4) & 0x01)
            
            record1 = DPrivateEquipmentLinkInfo.query.filter_by(id = self.id, lino = 0).first()
            record2 = DPrivateEquipmentLinkInfo.query.filter_by(id = self.id, lino = 1).first()
            if record1 == None:
                dict = {'is_allowed_access':access_state_1}
                newrecord = DPrivateEquipmentLinkInfo(self.id, 0, dict)
                db.session.add(newrecord)
            else:
                record1.is_allowed_access = access_state_1
                db.session.add(record1)
            if record2 == None:
                dict = {'is_allowed_access':access_state_2}
                newrecord = DPrivateEquipmentLinkInfo(self.id, 1, dict)
                db.session.add(newrecord)      
            else:
                record2.is_allowed_access = access_state_2
                db.session.add(record2)
            db.session.commit()
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

#1.2.35
class CSetAllowedAccessStatus():
    def __init__(self, id,dest_host,parameters,target    ):   
    
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 62
        self.is_allowed_access = parameters[0]
        self.lino = parameters[1]
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.is_allowed_access, self.lino)
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
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            record = DPrivateEquipmentLinkInfo.query.filter_by(id = self.id, lino=self.lino).first()
            if record == None:
                dict = {'is_allowed_access':bool(self.is_allowed_access)}
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict)
                db.session.add(newrecord)
            else:
                record.is_allowed_access = bool(self.is_allowed_access)
                db.session.add(record)
            db.session.commit()
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

#1.2.45 huo qu MAC xin xi
class CGetMacInfo():
    def __init__(self, id,dest_host,parameters,target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 87
        self.lino = parameters[0]#int
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.lino, self.lino)
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

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        
        if Status == 0:
            content_receive_data_pack = packet_receive[160:260]      
            content_receive_data = unpack('!50s50s', content_receive_data_pack)            ##########   parse data
            route_mac = content_receive_data[0].strip(' \x00')[2:].split('\x00')[0]
            switch_mac = content_receive_data[1].strip(' \x00')[2:].split('\x00')[0]
            record = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id, lino=self.lino).first()
            if record == None:
                dict = {'route_mac':route_mac, 'switch_mac':switch_mac}            
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict) # Create a new record, the DataBaseName is given by yourselves
                db.session.add(newrecord)
            else:
                record.route_mac = route_mac
                record.switch_mac = switch_mac
                db.session.add(record)
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

#1.2.46 she zhi MAC xin xi
class CSetMacInfo():
    def __init__(self, id,dest_host, parameters, target    ): 
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 #parameter1 the length of data
        self.Command_Code = 88
        self.lino = parameters[0] #Link Number
        self.route_mac = parameters[1]
        self.switch_mac = parameters[2]
        self.flag = 128 #0x80

    def PackContent(self):
        buf = ctypes.create_string_buffer(272)
        if self.lino == 0:
            route_mac = '0 ' + self.route_mac
            switch_mac = '1 ' + self.switch_mac
        else:
            route_mac = '2 ' + self.route_mac
            switch_mac = '3 ' + self.switch_mac            
        struct.pack_into('!BBHBB', buf, 0 , self.FunCode, self.Param1, self.Param2, self.Command_Code, self.lino)
        struct.pack_into('!19s', buf, 6, route_mac)
        struct.pack_into('!59s', buf, 56, switch_mac)
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

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            record = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id, lino=self.lino).first()
            if record == None:
                dict = {'route_mac':self.route_mac, 'switch_mac':self.switch_mac}            
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict) # Create a new record, the DataBaseName is given by yourselves
                db.session.add(newrecord)
            else:
                record.route_mac = self.route_mac
                record.switch_mac = self.switch_mac
                db.session.add(record)
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

#1.2.48
class CEnablelink(): 
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 #parameter1 the length of data
        self.Command_Code = 90
        self.Param = parameters[0] #is enabled
        self.lino = parameters[1] #link number

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.Param,self.lino)
        struct.pack_into('!B',buf,262,self.flag)

        #############    End   ##############
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
            record = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id, lino=self.lino).first()
            if record == None:
                dict = {'line_work_enable':bool(self.Param)}            
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict) # Create a new record, the DataBaseName is given by yourselves
                db.session.add(newrecord)
            else:
                record.line_work_enable = bool(self.Param)
                db.session.add(record)
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

#1.2.54
class CSetNatIPAddress():
    def __init__(self, id,dest_host, parameters, target    ):   
       
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 70
        self.Command_Code = 96
        self.IP_Addr = parameters[0]
        self.Mask = parameters[1]
        self.lino = parameters[2] 

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(80)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!' + str(len(self.IP_Addr)) + 's', buf, 5, self.IP_Addr)
        struct.pack_into('!' + str(len(self.Mask)) + 's', buf,37,self.Mask)
        struct.pack_into('!BB',buf,69,self.lino,self.flag)
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
                dict = {'nat_ipaddr':self.IP_Addr,'nat_ipmask':self.Mask}
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict)
                db.session.add(newrecord)
            else:
                record.nat_ipaddr = self.IP_Addr
                record.nat_ipmask = self.Mask
                db.session.add(record)
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

#1.2.55
class CEnableNat():
    def __init__(self, id,dest_host, parameters, target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 97
        self.isenabled = parameters[0] # 1-enable 0-disable
        self.lino = parameters[1] 

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.isenabled,self.lino)
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
                dict = {'nat_ip_enabled':bool(self.isenabled)}
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict)
                db.session.add(newrecord)
            else:
                record.nat_ip_enabled = bool(self.isenabled)
                db.session.add(record)
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

#1.2.56
class CGetNatConfig():
    def __init__(self, id,dest_host, parameters, target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 98
        self.Param = 0
        self.lino = parameters[0] 

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.Param,self.lino)
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
        
        if len(packet_receive) < 169:   ##change the size according the packet
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
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            content_receive_nat_config = packet_receive[160:172]
            content_receive_2 = unpack('!B3s4s4s',content_receive_nat_config)
            natflag = content_receive_2[0]
            ipaddr = socket.inet_ntoa(content_receive_2[2])
            ipmask = socket.inet_ntoa(content_receive_2[3]) 


            record = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id,lino=self.lino).first()
            if record == None:
                dict = {'nat_ip_enabled':bool(natflag),'nat_ipaddr':ipaddr,'nat_ipmask':ipmask}
                newrecord = DPrivateEquipmentLinkInfo(self.id,self.lino,dict)
                db.session.add(newrecord)
            else:
                record.nat_ip_enabled = natflag
                record.nat_ipaddr = ipaddr
                record.nat_ipmask = ipmask
                db.session.add(record)
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

