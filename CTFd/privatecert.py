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
#def IPHeader():
import thread, time
import Transport
from generalfunction import GenerateSN,GeneratePacketHeader,Confirm

##1.2.1 
class CImportCert():
    def __init__(self, id, dest_host, parameters, target):   

        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        #data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 2037 #data lenth
        #self.Param2 = 2039
        self.Command_Code = 4            #uchar
        self.Cert_Type = parameters[0]    #uchar, type:0-8, readonly?, ECC or RSA
        self.Peer_Ip = parameters[1]      #uchar[32], ip address
        self.Cert_Format = parameters[2]  #uchar, format:BASE64-0,DER-1
        self.Cert_Length = parameters[3]  #uint, length of content
        self.Cert_Content = parameters[4] #uchar[2000], content of cert
        self.flag = 128

    def PackContent(self):
        buf = ctypes.create_string_buffer(2048)   ###change the size
        Peer_Ip = (self.Peer_Ip + '\x00' * 32)[:32]
        Cert_Content = (self.Cert_Content + '\x00' * 2000)[:2000]
        struct.pack_into('!BBHBB32sB', buf, 0, self.FunCode,self.Param1, self.Param2,self.Command_Code, self.Cert_Type, Peer_Ip, self.Cert_Format)
        struct.pack_into('H2000sB', buf, 39, self.Cert_Length, Cert_Content ,self.flag)
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

#1.2.2 cha xun zheng shu lie biao
class CQueryCertList():
    def __init__(self, id, dest_host,  target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 2#data lenth

        self.Command_Code = 5  #uchar
        self.Cert_Type = 6     #uchar
        ################  End #####################
        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, \
            self.Command_Code, self.Cert_Type, self.flag)
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
        ################# Change From Here #################
        content_receive_head_pack = packet_receive[152:164]
        content_receive_head = unpack('!BBHBB2sL' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]         #P=S
        Length = content_receive_head[2]        #L=Command_Code
        #print '#####################',Length 
        Return_Code = content_receive_head[3]   #uchar
        Status = content_receive_head[4]        #uchar
        #print Return_Code,'######################################',Status
        reserve = content_receive_head[5]       #uchar[2]
        Cert_Number = content_receive_head[6]   #uint             
        if Status == 0:                          #if success, clear old
            existrecords = DPrivateCertInfo.query.filter_by(id=self.id).all()
            dict = {}
            for existrecord in existrecords:
                dict.update({existrecord.cert_name:existrecord})
            existrecordlist = dict.keys()
            

            for i in range(Cert_Number):
                cert_list_receive_pack = packet_receive[164 + 30 * i : 194 + 30 * i]
                cert_list_receive = unpack('!30s', cert_list_receive_pack)
                Cert_FileName = cert_list_receive[0].strip('\x00').split('\x00') [0] #uchar[30]
                Cert_Type = 5
                if Cert_FileName.find('DMS') != -1:
                    Cert_Type = 1
                else:
                    Cert_Type = 5
                if Cert_FileName not in existrecordlist:
                    newrecord = DPrivateCertInfo(self.id,Cert_FileName, Cert_Type)
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
        if packet_receive == None: ## time out
            return -2
        status = self.ParsePacket(packet_receive)
        if status == None:
            return -1
        else:
            return status

 #1.2.6 tian jia ce lue

#1.2.7 shan chu zheng shu
class CDeleteCert():
    def __init__(self, id, dest_host, parameters,  target    ):   

        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 33 #data lenth

        self.Command_Code = 12      #uchar
        self.IpAddr = parameters[0]  #uchar[32], cert ip address

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(48)   ###change the size 
        IpAddr = (self.IpAddr + '\x00' * 32)[:32]
        content = struct.pack_into('!BBHB32sB', buf, 0, self.FunCode, self.Param1, self.Param2, \
            self.Command_Code, IpAddr, self.flag)
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

#1.2.8 cha xun zheng shu
class CQueryCert():
    def __init__(self, id,dest_host, parameters,  target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 33 #data lenth

        self.Command_Code = 13      #uchar
        self.IpAddr = parameters[0]  #uchar[32]
        ################  End #####################
        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(48)   ###change the size
        IpAddr = (self.IpAddr + '\x00' * 32)[:32].encode('utf-8')
        content = struct.pack_into('!BBHB32sB', buf, 0, self.FunCode, self.Param1, self.Param2,  self.Command_Code, IpAddr, self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        #sn = GenerateSN()
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
        ################# Change From Here #################
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
        if Status == 0:                          
            cert_receive_pack = packet_receive[160:416]
            cert_receive = unpack('!32s32s64s32s32s64s', cert_receive_pack)
            #print cert_receive
            #for i in cert_receive:
            #    print "########", i
            province = cert_receive[0].strip('\x00').split('\x00')[0].decode('gbk')
            city = cert_receive[1].strip('\x00').split('\x00')[0].decode('gbk')
            organ = cert_receive[2].strip('\x00').split('\x00')[0].decode('gbk')
            depart = cert_receive[3].strip('\x00').split('\x00')[0].decode('gbk')
            name = cert_receive[4].strip('\x00').split('\x00')[0].decode('gbk')
            email = cert_receive[5].strip('\x00').split('\x00')[0].decode('gbk')
            
            record = DPrivateCertInfo.query.filter_by(id=self.id,cert_name=self.IpAddr).first()
            if record == None:
                pass
            else:
                record.province = province
                record.city = city
                record.organ = organ
                record.depart = depart
                record.name = name
                record.email = email
                db.session.add(record)
            db.session.commit()
        return [Status,{'province':province, "city":city, "organ":organ, "depart":depart, "name":name, "email":email}]

    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2,{}]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1,{}]
        else:
            return status

#1.2.36  
class RenameCert():
    def __init__(self, id,dest_host, parameters,target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 65
        self.Command_Code = 66
        self.IpAddr = parameters[0]#string/Certificate IP
        self.RenIpAddr = parameters[1]#string/rename ip
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(80)   ###change the size
        IpAddr = (self.IpAddr + '\x00' * 32)[:32]
        RenIpAddr = (self.RenIpAddr + '\x00' * 32)[:32]
        struct.pack_into('!BBHB32s32sB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, IpAddr, RenIpAddr, self.flag)
        return  buf.raw
    def PackPacket(self):
        
        #sn = GenerateSN()
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
        if Status == 0:
            record = DPrivateCertInfo.query.filter_by(id=self.id, cert_name= self.IpAddr).first()
            if record != None:
                record.cert_name = self.RenIpAddr
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
           

#1.2.47
class CRenameManagementCert():
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 65 #parameter1 the length of data
        self.Command_Code = 89
        self.IpAddr = parameters[0] #the ip of Certificate
        self.RenIpAddr = parameters[1] #the ip of rename

        self.flag = 128 #0x80

    def PackContent(self):
        buf = ctypes.create_string_buffer(80)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!'+str(len(self.IpAddr))+'s',buf,5,self.IpAddr)
        struct.pack_into('!'+str(len(self.RenIpAddr))+'s',buf,41,self.RenIpAddr)
        struct.pack_into('!B',buf,77,self.flag)
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
        #Param = content_receive_head_pack[]
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            record = DPrivateCertInfo.query.filter_by(id=self.id, cert_name= self.IpAddr).first()
            if record != None:
                record.cert_name = self.RenIpAddr
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
            
