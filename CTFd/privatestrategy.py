#!/usr/bin/env python
# coding=utf-8
from flask_sqlalchemy import SQLAlchemy

from CTFd import models
from CTFd.utils import whichEncode
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

# 1.2.6    add strategy
class CAddStrategy():
    def __init__(self, id, dest_host, parameters,  target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 191 #data lenth

        self.Command_Code = 9                                   #uchar
        self.pad = '\x00' * 3               #uchar[3], pad
        self.CID = parameters[0]               #uchar[5], word[0-3]:ChannelID
        self.Source_Begin_IP = parameters[1]   #uchar[32], Source Begin IP
        self.Source_End_IP = parameters[2]     #uchar[32], Source End   IP
        self.Dest_Begin_IP = parameters[3]     #uchar[32], Dest   Begin IP
        self.Dest_End_IP = parameters[4]       #uchar[32], Dest   End   IP
        self.Port_Source_Begin = parameters[5] #uchar[2],  Source Begin Port
        self.Port_Source_End = parameters[6]   #uchar[2],  Source End   Port
        self.Port_Dest_Begin = parameters[7]   #uchar[2],  Dest   Begin Port
        self.Port_Dest_End = parameters[8]     #uchar[2],  Dest   End   Port
        self.Dirction = parameters[9]         #uchar, dirction:1-goout,2-goin,0-twoway
        self.Protocol = parameters[10]         #uchar, protocol:0-all,1-ICMP,2-TCP,3-UDP
        self.Work_Mode = parameters[11]        #uchar, workmode:0-encrypt,1-visible,2-selectencrypt;
        self.NatMode = parameters[12]          #uchar, netmode:0-noNAT,1-sourceNAT
        self.Policy_Name = parameters[13]      #uchar[40], policy name
        self.Policy_limit = parameters[14]     #uchar, policy flowrate(Mb)
        self.Policy_level = parameters[15]     #uchar, level:0,1,2
        ################  End #####################
        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(208)   ###change the size
        pad = (self.pad + '\x00' * 3)[:3]
        Source_Begin_IP = (self.Source_Begin_IP + '\x00' * 32)[:32]
        Source_End_IP = (self.Source_End_IP + '\x00' * 32)[:32]
        Dest_Begin_IP = (self.Dest_Begin_IP + '\x00' * 32)[:32]
        Dest_End_IP = (self.Dest_End_IP + '\x00' * 32)[:32]
        Policy_Name = (self.Policy_Name + '\x00' * 40)[:40]
        struct.pack_into('!BB',buf,0,self.FunCode,self.Param1)
        struct.pack_into('!H',buf,2,self.Param2)
        struct.pack_into('!B', buf,4,self.Command_Code)
        struct.pack_into('L',buf,8,self.CID)
        struct.pack_into('!32s32s32s32s',buf,13,Source_Begin_IP, Source_End_IP,Dest_Begin_IP, Dest_End_IP)
        #print Source_Begin_IP,Source_End_IP,Dest_Begin_IP,Dest_End_IP,"***************"
        struct.pack_into('HHHH',buf,141,self.Port_Source_Begin,self.Port_Source_End,self.Port_Dest_Begin,self.Port_Dest_End)
        struct.pack_into('!BBBB40sBB',buf,149,self.Dirction,self.Protocol, self.Work_Mode,self.NatMode, Policy_Name, self.Policy_limit, self.Policy_level)
        '''struct.pack_into('!BBHB3s5s32s32s32s32s2s2s2s2sBBBB40sBBB',buf,0,self.FunCode,self.Param1,self.Param2,\
            self.Command_Code, pad, CID, Source_Begin_IP, Source_End_IP, \
            Dest_Begin_IP, Dest_End_IP, Port_Source_Begin, Port_Source_End, \
            Port_Dest_Begin, Port_Dest_End, self.Dirction,self.Protocol, self.Work_Mode, \
            self.NatMode, Policy_Name, self.Policy_limit, self.Policy_level, self.flag)'''
        struct.pack_into('!B',buf,195,self.flag)
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

#1.2.11 cha xun ce lue lie biao
class CQueryStrategyList():
    def __init__(self, id, dest_host, parameters,  target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 #data lenth

        self.Command_Code = 17     #uchar
        self.Param = 16
        self.channel_id = parameters[0]   #uchar[256], word[0-3]:CID
        self.flag = 128

    def PackContent(self):
        buf = ctypes.create_string_buffer(272)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.Param)
        struct.pack_into('L', buf, 6, self.channel_id)
        struct.pack_into('!B',buf,262,self.flag)
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
        content_receive_head_pack = packet_receive[152:162]
        content_receive_head = unpack('!BBHBB2sH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]         #P=S
        Length = content_receive_head[2]        #L=Command_Code
        Return_Code = content_receive_head[3]   #uchar
        Status = content_receive_head[4]        #uchar
        reserve = content_receive_head[5]       #uchar[2]
        Policy_Number = unpack('H', packet_receive[160:162])[0]   #uint        
        if Return_Code != self.Command_Code + 1:
            return None
        policy_list = range(Policy_Number)
        return [Status, Policy_Number, policy_list]        
    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2 , 0, []]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1, 0, []]
        else:
            return status

#1.2.12 cha xun ce lue nei rong
class CQueryPolicy():
    def __init__(self, id,dest_host, parameters,  target    ):   
       
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 #data lenth

        self.Command_Code = 18     #uchar
        self.Param = 0
        self.channel_id = parameters[0]
        self.strategy_id = parameters[1]

        self.flag = 128

    def PackContent(self):
        buf = ctypes.create_string_buffer(272)   ###change the size
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code, self.Param)
        struct.pack_into('L',buf,6,self.channel_id)
        struct.pack_into('L',buf,10,self.strategy_id)
        struct.pack_into('!B',buf,262,self.flag)
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
        content_receive_head_pack = packet_receive[152:160]
        content_receive_head = unpack('!BBHBB2s', content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]         #P=S
        Length = content_receive_head[2]        #L=Command_Code
        Return_Code = content_receive_head[3]   #uchar
        Status = content_receive_head[4]        #uchar
        reserve = content_receive_head[5]       #uchar[2]        
        if Return_Code != self.Command_Code + 1:
            return None
        record = None
        if Status == 0:
            policy_receive_pack = packet_receive[160:342]
            policy_receive = unpack('32s32s32s32sHHHHBBBB40sBB', policy_receive_pack)
            Source_Begin_IP = policy_receive[0].strip('\x00').split('\x00')[0]
            Source_End_IP = policy_receive[1].strip('\x00').split('\x00')[0]
            Dest_Begin_IP = policy_receive[2].strip('\x00').split('\x00')[0]
            Dest_End_IP = policy_receive[3].strip('\x00').split('\x00')[0]
            Port_Source_Begin = policy_receive[4]
            Port_Source_End = policy_receive[5]
            Port_Dest_Begin = policy_receive[6]
            Port_Dest_End = policy_receive[7]
            
            Direction = policy_receive[8]
            Protocol = policy_receive[9]
            WorkMode = policy_receive[10]
            NatMode = policy_receive[11]
            Policy_Name1 = policy_receive[12].strip('\x00').split('\x00')[0]
            whichcode = whichEncode(Policy_Name1)
            if whichcode == 1:
                Policy_Name = Policy_Name1
            elif whichcode == 2:
                Policy_Name = Policy_Name1.decode('gbk').encode('utf-8')
            Policy_limit = policy_receive[13]
            Policy_level = policy_receive[14]
            strategis = DPrivateSecurityStrategy.query.filter_by(id=self.id,channelnumber=self.channel_id).all()
            record = strategis[self.strategy_id]
            if record != None:
                record.Source_Begin_IP = Source_Begin_IP
                record.Source_End_IP = Source_End_IP
                record.Dest_Begin_IP = Dest_Begin_IP
                record.Dest_End_IP = Dest_End_IP

                record.Port_Source_Begin = Port_Source_Begin
                record.Port_Source_End = Port_Source_End
                record.Port_Dest_Begin = Port_Dest_Begin
                record.Port_Dest_End = Port_Dest_End
                
                record.Direction = Direction
                record.Protocol = Protocol
                record.WorkMode = WorkMode
                record.NatMode = bool(NatMode)
                record.Policy_Name = Policy_Name
                record.Policy_limit = Policy_limit
                record.Policy_level = Policy_level
            else:
                newrecord = DPrivateSecurityStrategy(self.id,self.channel_id,self.strategy_id, Source_Begin_IP, Source_End_IP, Dest_Begin_IP, Dest_End_IP, Port_Source_Begin, Port_Source_End,Port_Dest_Begin, Port_Dest_End, Direction, Protocol, WorkMode, NatMode,Policy_Name, Policy_limit, Policy_level)
        return [Status,record]
        

    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2,None]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1,None]
        else:
            return status

class CDeleteSecurityStrategy():
    def __init__(self, id, dest_host, parameters, target    ):

        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 9
        self.Param1 = 0
        self.channelnumber = parameters[0]
        self.strategynumber = parameters[1]

        self.flag = 128
    def PackContent(self):

        buf = ctypes.create_string_buffer(16)  ###change the size 
        content = struct.pack_into('!BBHLB', buf, 0, self.FunCode, self.Param1, self.channelnumber, self.strategynumber, self.flag)

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
        status = content_receive_head[1]
        Length = content_receive_head[2]
        return status
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
