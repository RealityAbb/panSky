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

#1.2.40
class BackupConfigFile():
    def __init__(self, id,dest_host,parameters,target    ):   
 
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 6
        self.Command_Code = 78
        self.File_Type = parameters[0]#int
        self.Offset = parameters[1]  #string
        
        self.flag = 128

        self.filepath = parameters[2]
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.File_Type)
        struct.pack_into('L', buf, 6, self.Offset)
        struct.pack_into('!B', buf, 10, self.flag)
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
        Flag = 0
        Data_Len = 0
        if Status == 0:
            content_receive_data_pack = packet_receive[160:160+2051]      
            Flag = unpack('B',content_receive_data_pack[0])[0]
            Data_Len = unpack('H',content_receive_data_pack[1:3])[0]
            Data = unpack('!' + str(Data_Len) + 's', content_receive_data_pack[3 : 3 + Data_Len])[0]

            file = open(self.filepath,'a')
            
            file.write(Data)
            file.close()
        return [Status, Flag, Data_Len]
    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2, 0, 0]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1, 0 ,0]
        else:
            return status         
