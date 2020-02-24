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

#1.2.18 shezhixitongshijian 
class CSetSystemTime():
    def __init__(self, id,dest_host,parameters,target    ):   

        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 8
        self.Command_Code = 30
        self.year = parameters[0]
        self.month = parameters[1]
        self.day = parameters[2]
        self.hour = parameters[3]
        self.minute = parameters[4]
        self.second = parameters[5]

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBHBBBBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.year,self.month,self.day,self.hour,self.minute,self.second,self.flag)
        
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

#1.2.19 shezhigongzuomoshi  
class CSetWorkModel():
    def __init__(self, id,dest_host,  parameters,target    ):   

        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 2
        self.Command_Code = 31
        self.encrypt = parameters[0]#0-encryption 1-optional 2-mingtong

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.encrypt,self.flag)
        
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'work_model':bool(self.encrypt)}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.work_model = bool(self.encrypt)
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

#1.2.21 shezhizuidajiamicishu 
class CSetMaxEncryptTimes():
    def __init__(self, id,dest_host,parameters,target    ):   
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 5
        self.Command_Code = 34
        self.max = parameters[0]#set the number(10 thousand times)
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBLB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.max,self.flag)
        
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'dk_encrypt_times_max':self.max // 10000}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.dk_encrypt_times_max = self.max // 10000
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

#1.2.22 shezhimiyaozuichangshengcunzhouqi 
class CSetLongestSurvivalPeriodofKey():
    def __init__(self, id,dest_host,parameters,target    ):   
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 8
        self.Command_Code = 35
        self.cycle = parameters[0]#hour 1-100

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!LB', buf, 8, self.cycle, self.flag)

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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'dk_lifetime':self.cycle}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.dk_lifetime = self.cycle
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

#1.2.24 huoquxitongshijian 
class CGetSystemTime():
    def __init__(self, id,dest_host, target    ):   

        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        self.systemtime = ''
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1
        self.Command_Code = 47

        
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
            content_receive_data_pack = packet_receive[160:164]      
            content_receive_data = unpack('!L', content_receive_data_pack)    
            
            timegap = content_receive_data[0]
            self.systemtime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timegap))        
        return Status
    def SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2, self.systemtime]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1, self.systemtime]
        else:
            return [status, self.systemtime] 

#1.2.27 shezhixieshangchaoshishijian 
class CSetTimeout():
    def __init__(self, id,dest_host,parameters,target    ):   
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 54
        self.timeout = parameters[0]#second

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.timeout)
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'dk_retry_interval':self.timeout}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.dk_retry_interval = self.timeout
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


#1.2.38
class CSetSpingSendInterval():
    def __init__(self, id,dest_host, parameters, target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 75
        self.sping_send_interval = parameters[0]#int/Transmission time interval
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.sping_send_interval)
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'sping_send_interval':self.sping_send_interval}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.sping_send_interval = self.sping_send_interval
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


#1.2.39
class CSetSpingResponseTimeout():
    def __init__(self, id,dest_host, parameters, target    ):   
     
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 77
        self.sping_response_timeout = parameters[0]#int/Over time
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.sping_response_timeout)
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'sping_response_timeout':self.sping_response_timeout}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.sping_response_timeout = self.sping_response_timeout
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
                        


#1.2.59            
class CSetPlateformState():
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 6
        self.Command_Code = 102
        self.secplateformflag = parameters[0]

        self.flag = 128 #0x80


    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.secplateformflag,self.flag)
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'secplateformflag':bool(self.secplateformflag)}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.secplateformflag = bool(self.secplateformflag)
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

#1.2.60            
class CGetPlateformState():
    def __init__(self, id,dest_host,target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 103

        self.flag = 128 #0x80


    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
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
            secplateformflag = unpack('!B',packet_receive[158])[0]
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'secplateformflag':bool(secplateformflag)}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.secplateformflag = bool(secplateformflag)
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



#1.2.57
class CSetIPsecParameter():
    def __init__(self, id,dest_host, parameters, target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 99
        self.ipsec_parameter = parameters[0] 

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into('!'+str(len(self.ipsec_parameter))+'s',buf,6,self.ipsec_parameter)
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'ipsec_parameter':self.ipsec_parameter}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.ipsec_parameter = self.ipsec_parameter
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

#1.2.58
class CGetIPsecParameter():
    def __init__(self, id,dest_host, target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 100

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code)
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
            content_receive_data_pack = packet_receive[158:414]
            content_receive_data = unpack('!256s',content_receive_data_pack)[0]
            ipsec_parameter = content_receive_data.strip('\x00').split('\x00')[0]
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'ipsec_parameter':ipsec_parameter}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.ipsec_parameter = ipsec_parameter
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
