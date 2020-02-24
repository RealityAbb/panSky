#!/usr/bin/env python
# coding=utf-8
from flask.ext.sqlalchemy import SQLAlchemy

from CTFd.models import db, EquipmentsStatus, ChannelNumber, ChannelStatus, DSecurityStrategy
from CTFd import models
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from struct import *
from time import ctime,sleep
from os import system

import socket
import struct
import ctypes
import datetime
import thread, time
import Transport
from generalfunction import GenerateSN,GeneratePacketHeader,Confirm

class CReplaceCert():
    def __init__(self, id,dest_host, Parameter, target    ):
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 5
        self.Param1 = 0  #parameter 1
        self.peer_ip = socket.inet_aton(Parameter[0])  #channel code
        self.cert_content = Parameter[1]
        self.flag = 128 # 0x80
    def PackContent(self):
        datalen = 4 + len(self.cert_content)
        
        s1 = struct.pack('!BBH', self.FunCode, self.Param1, datalen)
        s2 = struct.pack('4s', self.peer_ip)
        s3 = struct.pack(str(len(self.cert_content)) + 's', self.cert_content)
        s4 = struct.pack('!B', self.flag)
        s = s1 + s2 + s3 + s4
        s5 = (16 - len(s) % 16) * '\x00'
        return s + s5
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        Packet = snh + PacketHeader + PacketContent + confirmh

        return Packet

    def  ParsePacket(self, packet_receive):
        try:
            ip_header = packet_receive[0:20]
            ip_protocol = unpack('!B',ip_header[9])[0]
            if ip_protocol != 254:
                return None
            snh = packet_receive[20:24]
            sn = unpack('!L', snh)[0]
            if sn != self.sn + 1:
                return None
        except:
            return None
       
        content_receive_head_pack = packet_receive[152:156]
        content_receive_head =  unpack('!BBH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        status = content_receive_head[1]
        recordnumber = content_receive_head[2]
        
        if FunCode != self.FunCode:
            return None   
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
class CQueryEquipmentStatus():
    def __init__(self, id, dest_host, target    ):
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the  data
        self.FunCode = 1
        self.Param1 = 0
        self.Param2 = 0

        self.flag = 128
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)
        return  buf.raw
    def PackPacket(self):
       
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        
        packet_send = snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        
        snh=packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None
        if len(packet_receive) < 188:
            return None
        content_receive_pack = packet_receive[152:188]
        content_receive = unpack('!BBHBBBBLLLLLLL' , content_receive_pack)
        FunCode = content_receive[0]

        if FunCode != self.FunCode:
            return None
        Param = content_receive[1]
        Length = content_receive[2]
        status = content_receive[3]
        workmodel = content_receive[4]
        sign = content_receive[5]
        restain= content_receive[6]
        encrypt = content_receive[7]
        decrypt = content_receive[8]
        errorencrypt = content_receive[9]
        errordecrypt = content_receive[10]
        send = content_receive[11]
        receive = content_receive[12]
        errorreceive = content_receive[13]

        equipmentstatus = EquipmentsStatus.query.filter_by(id = self.id).first()
        
        if equipmentstatus == None:
            #print 'equipmentstatus'
            newrecord = EquipmentsStatus(self.id,status, workmodel, sign, restain, encrypt, decrypt, errorencrypt, errordecrypt, send, receive, errorreceive)
            db.session.add(newrecord)
            db.session.commit()
        else:
            equipmentstatus.status = status
            equipmentstatus.workmodel = workmodel
            equipmentstatus.sign = sign
            equipmentstatus.restain = restain
            equipmentstatus.encrypt = encrypt
            equipmentstatus.decrypt = decrypt
            equipmentstatus.enrorencrypt = errorencrypt
            equipmentstatus.errordecrypt = errordecrypt
            equipmentstatus.send = send
            equipmentstatus.receive = receive
            equipmentstatus.errorreceive = errorreceive
            db.session.add(equipmentstatus)
            db.session.commit()
        return  0
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

 #  Set Channel Work Model'''
class CSetChannelWorkmodel():
    def __init__(self, id,dest_host, Parameter, target    ):
       
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 2
        self.workmodel = Parameter[0] #parameter 1
        self.channelnumber = Parameter[1]  #channel code
        self.flag = 128 # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.workmodel, self.channelnumber, self.flag)
        return  buf.raw
    def PackPacket(self):
       
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        
        Packet = snh + PacketHeader + PacketContent + confirmh

        return Packet

    def  ParsePacket(self, packet_receive):

        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:154]
        content_receive = unpack('!BB' , content_receive_pack)
        FunCode = content_receive[0]
        status = content_receive[1]
        if FunCode != self.FunCode:
            return None
        if status == 0:
            record = ChannelStatus.query.filter_by(id=self.id,channelnumber=self.channelnumber).first()
            if record != None:
                record.mode = self.workmodel
                db.session.add(record)
                db.session.commit()
        return  status
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
 #  Add Channel'''
class AddChannel():
    def __init__(self, id,dest_host, Parameter, target    ):
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 4
        self.Param1 =  0 #parameter 1
        self.Param2 = 10
        self.oip = socket.inet_aton(Parameter[0])
        self.eip = socket.inet_aton(Parameter[1])
        self.workmodel = Parameter[2]

        self.flag = 128 # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBH4s4sHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.oip,self.eip,self.workmodel,self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send =  snh + PacketHeader + PacketContent + confirmh       

        return packet_send

    def  ParsePacket(self, packet_receive):
        #Receive()
        if len(packet_receive) < 154:
           return None       
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None
        content_receive_pack = packet_receive[152:154]
        content_receive = unpack('!BB', content_receive_pack)
        FunCode = content_receive[0]
        status = content_receive[1]
        if FunCode != self.FunCode:
            return None
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
class QueryChannel():
    def __init__(self, id,dest_host, target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        self.FunCode = 3
        self.Param1 = 0
        self.Param2 = 0

        self.flag = 128
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)  
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)
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
        Param = content_receive_head[1]
        Length = content_receive_head[2]

        count = Length/2       
        ExistRecords = ChannelStatus.query.filter_by(id = self.id).all()
        ExistChannelNumbers = []
        ChannelNumbers = []
        for existrecord in ExistRecords:
            ExistChannelNumbers.append(existrecord.channelnumber)
        for i in range(count):
            messagec = packet_receive[156+2 * i : 158 + 2 * i]
            channelnumber = unpack('!H',messagec)[0]
            ChannelNumbers.append(channelnumber)
            ### if the record is not in the database ###
            if channelnumber not in ExistChannelNumbers:
                newrecord = ChannelStatus(self.id, channelnumber)
                db.session.add(newrecord)
        for existrecord in ExistRecords:
            if existrecord.channelnumber not in ChannelNumbers:
                db.session.delete(existrecord)
        db.session.commit()
        return  0
        ###########  END ##################
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
class CDeleteChannel():
    def __init__(self, id,dest_host, Parameter, target    ):
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 14
        self.Param1 = 0  #parameter 1
        self.Param2 = Parameter[0]  #channel code
        self.flag = 128 # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        Packet =  snh + PacketHeader + PacketContent + confirmh

        return Packet

    def  ParsePacket(self, packet_receive):
        #Receive()
        if len(packet_receive) < 154:
            return None       
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:154]
        print repr(content_receive_pack)
        content_receive = unpack('!BB', content_receive_pack)
        FunCode = content_receive[0]
        status = content_receive[1]
        #print 'status = ', status
        if FunCode != self.FunCode:
            return None
        if status == 0:
            channelstatus = ChannelStatus.query.filter_by(id =self.id, channelnumber = self.Param2).first()
            db.session.delete(channelstatus)
            securitystrategys =DSecurityStrategy.query.filter_by(id=self.id,channelnumber=self.Param2).all()
            for securitystrategy in securitystrategys:
                db.session.delete(securitystrategy)
            db.session.commit()
        return  status
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
class CQueryChannelStatus():
    def __init__(self, id, dest_host, Parameter, target    ):
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 6
        self.Param1 = 0  #parameter 1
        self.Param2 = Parameter[0]  #channelnumber
        self.flag = 128 # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        Packet = snh + PacketHeader + PacketContent + confirmh

        return Packet
    def  ParsePacket(self, packet_receive):
        #Receive()
        if len(packet_receive) < 196:
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
        content_receive_head = unpack('!BBH', content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        status = content_receive_head[1]
        if status != 0:
            return status
        Length = content_receive_head[2]        
        content_receive_data_pack = packet_receive[156:196]
        content_receive_data = unpack('!4sBBBBLLLLLLLL' , content_receive_data_pack)

        uip = socket.inet_ntoa(content_receive_data[0]).decode('utf-8')
        mode = content_receive_data[1]
        mainsub = content_receive_data[2]
        strategy = content_receive_data[3]
        negostatus = content_receive_data[4]
        timegap = content_receive_data[5]
        successtime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timegap))
        encrypt = content_receive_data[6]
        decrypt = content_receive_data[7]
        errorencrypt = content_receive_data[8]
        errordecrypt = content_receive_data[9]
        send = content_receive_data[10]
        receive = content_receive_data[11]
        errorreceive = content_receive_data[12]
        channelstatus = ChannelStatus.query.filter_by(id = self.id, channelnumber = self.Param2).first()
        if channelstatus == None:
            #print 'equipmentstatus'
            newrecord = ChannelStatus(self.id, self.channelnumber, uip, mode, mainsub, strategy, negostatus, successtime, encrypt, decrypt, errorencrypt, errordecrypt, send, receive, errorreceive)
            db.session.add(newrecord)
            db.session.commit()
        else:
            channelstatus.uip = uip
            channelstatus.mode = mode
            channelstatus.mainsub = mainsub
            channelstatus.strategy = strategy
            channelstatus.negostatus = negostatus
            channelstatus.successtime = successtime
            channelstatus.encrypt = encrypt
            channelstatus.decrypt = decrypt
            channelstatus.errorencrypt = errorencrypt
            channelstatus.errordecrypt = errordecrypt
            channelstatus.send = send
            channelstatus.receive = receive
            channelstatus.errorreceive = errorreceive
            db.session.add(channelstatus)
            db.session.commit()
        return  status
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
class CResetChannel():
    def __init__(self, id,dest_host,Parameter,target    ):
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 11
        self.Param1 = 0  #parameter 1
        self.Param2 = Parameter[0]  #channel code
        self.flag = 128 # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        Packet =  snh + PacketHeader + PacketContent + confirmh

        return Packet

    def  ParsePacket(self, packet_receive):

        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:154]
        print repr(content_receive_pack)
        content_receive = unpack('!BB' , content_receive_pack)
        FunCode = content_receive[0]
        status = content_receive[1]
        if FunCode != self.FunCode:
            return None
        return  status
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
############ Channel Security  Strategy ##############
class CQuerySecurityStrategy():
    def __init__(self, id,dest_host, Parameter, target    ):

        #self.src_host = GetHostIP()
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 7
        self.Param1 = 0
        self.channelnumber = Parameter[0] # int
        #print self.channelnumber

        self.flag = 128
    def PackContent(self):

        buf = ctypes.create_string_buffer(16)  ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.channelnumber, self.flag)

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
        status = content_receive_head[1]
        if status != 0:
            return status
        Length = content_receive_head[2]

        count = Length/32  
        if count == 0:
            return status
        # delete  existing records.
        ExistRecords = DSecurityStrategy.query.filter_by(id = self.id, channelnumber=self.channelnumber).all()
        for existrecord in ExistRecords:
            db.session.delete(existrecord)
        db.session.commit()

        for i in range(count):
            content_receive_data_pack = packet_receive[156 + 32 * i : 188 + 32 * i]
            #print repr(content_receive_data_pack)
            content_receive_data = unpack('!L4s4s4s4sBBBBHHHH', content_receive_data_pack)
            #print content_receive_data
            strategynumber = content_receive_data[0]

            SrcIP =  socket.inet_ntoa(content_receive_data[1])
            SrcIPMask = socket.inet_ntoa(content_receive_data[2])
            DstIP = socket.inet_ntoa(content_receive_data[3])
            DstIPMask = socket.inet_ntoa(content_receive_data[4])
            direction_dict = ['双向','正向','反向']
            try:
                Direction = direction_dict[content_receive_data[5]]
            except:
                Direction = '未知'
            protocol_dict = ['全部', 'ICMP', 'TCP', 'UDP']
            try:
                Protocol = protocol_dict[content_receive_data[6]]
            except:
                protocol = '未知'
            mode_dict = ['加密', '明文', '可选']
            try:
                Mode = mode_dict[content_receive_data[7]]
            except:
                Mode = '未知'
            Reserved = content_receive_data[8]

            SrcPortMin = content_receive_data[9]
            SrcPortMax = content_receive_data[10]
            DstPortMin = content_receive_data[11]
            DstPortMax = content_receive_data[12]

            newrecord =  DSecurityStrategy(self.id, self.channelnumber, strategynumber, SrcIP, SrcIPMask, DstIP, DstIPMask, Direction, Protocol, Mode, Reserved, SrcPortMin, SrcPortMax, DstPortMin, DstPortMax)
            db.session.add(newrecord)
        db.session.commit()
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
class CDeleteSecurityStrategy():
    def __init__(self, id, dest_host, Parameter, target    ):

        #self.src_host = GetHostIP()
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 9
        self.Param1 = 0
        self.channelnumber = Parameter[0]
        self.strategynumber = Parameter[1]
        #print self.channelnumber

        self.flag = 128
    def PackContent(self):

        buf = ctypes.create_string_buffer(16)  ###change the size 
        content = struct.pack_into('!BBHLB', buf, 0, self.FunCode, self.Param1, self.channelnumber, self.strategynumber, self.flag)

        return  buf.raw
    def PackPacket(self):
        #IPHeader = GenerateIPHeader(self.src_host, self.dest_host)
        #sn = GenerateSN()
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        #Packet = IPHeader + snh + PacketHeader + PacketContent + confirmh
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
        #print 'status =', status
        if status == 0: # success
            record = DSecurityStrategy.query.filter_by(id = self.id, channelnumber = self.channelnumber, strategynumber = self.strategynumber).first()
            db.session.delete(record)
            db.session.commit()
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
class CAddSecurityStrategy():
    def __init__(self, id, dest_host, Parameter, target    ):

        self.id = id
        self.dest_host = dest_host

        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 8
        self.Param1 = 0  #parameter 1
        self.channelnumber = Parameter[0]  #channelnumber
        self.strategynumber = Parameter[1]
        self.SrcIP = socket.inet_aton(Parameter[2])
        self.SrcIPMask = socket.inet_aton(Parameter[3])
        self.DstIP = socket.inet_aton(Parameter[4])
        self.DstIPMask = socket.inet_aton(Parameter[5])
        self.Direction = Parameter[6]
        self.Protocol = Parameter[7]
        self.Mode = Parameter[8]
        self.Reserved = Parameter[9]
        self.SrcPortMin = Parameter[10]
        self.SrcPortMax = Parameter[11]
        self.DstPortMin = Parameter[12]
        self.DstPortMax = Parameter[13]

        self.flag = 128  # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(48)
        struct.pack_into('!BBHL', buf, 0, self.FunCode, self.Param1, self.channelnumber, self.strategynumber)
        struct.pack_into('!4s4s4s4s',buf,8, self.SrcIP, self.SrcIPMask, self.DstIP, self.DstIPMask)
        struct.pack_into('BBBB', buf, 24, self.Direction, self.Protocol, self.Mode, self.Reserved)
        struct.pack_into('!HHHH',buf,28, self.SrcPortMin, self.SrcPortMax, self.DstPortMin, self.DstPortMax)
        struct.pack_into('!B',buf, 36, self.flag)
        return  buf.raw
    def PackPacket(self):
        #IPHeader = GenerateIPHeader(self.src_host, self.dest_host)
        #sn = GenerateSN()
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        packet_send = snh + PacketHeader + PacketContent + confirmh
        return packet_send

    def  ParsePacket(self, packet_receive):
        #Receive()
        # if len(packet_receive) < 154:
        #     return None       
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_pack = packet_receive[152:154]
        content_receive = unpack('!BB', content_receive_pack)
        FunCode = content_receive[0]
        status = content_receive[1]
        if FunCode != self.FunCode:
            return None
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
class CModifySecurityStrategy():
    def __init__(self, id, dest_host, Parameter, target    ):
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        # the 
        self.FunCode = 15
        self.Param1 = 0  #parameter 1
        self.Param2 = Parameter[0]  #channelnumber
        self.strategynumber = Parameter[1] #strategynumber

        self.SrcIP = socket.inet_aton(Parameter[2])
        self.SrcIPMask = socket.inet_aton(Parameter[3])
        self.DstIP = socket.inet_aton(Parameter[4])
        self.DstIPMask = socket.inet_aton(Parameter[5])

        self.Direction = Parameter[6]
        self.Protocol = Parameter[7]
        self.Mode = Parameter[8]
        self.Reserved = Parameter[9]

        self.SrcPortMin = Parameter[10]
        self.SrcPortMax = Parameter[11]
        self.DstPortMin = Parameter[12]
        self.DstPortMax = Parameter[13]

        self.flag = 128  # 0x80
        # using in db
        self.dbSrcIP = Parameter[2]
        self.dbSrcIPMask = Parameter[3]
        self.dbDstIP = Parameter[4]
        self.dbDstIPMask = Parameter[5] 
    def PackContent(self):
        buf = ctypes.create_string_buffer(48)
        content = struct.pack_into('!BBHL4s4s4s4sBBBBHHHHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.strategynumber, self.SrcIP,
            self.SrcIPMask, self.DstIP, self.DstIPMask, self.Direction, self.Protocol, self.Mode, self.Reserved,
            self.SrcPortMin, self.SrcPortMax, self.DstPortMin, self.DstPortMax, self.flag)
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

        content_receive_pack = packet_receive[152:154]
        content_receive = unpack('!BB' , content_receive_pack)
        FunCode = content_receive[0]
        if FunCode != self.FunCode:
            return None
        status = content_receive[1]
        if status == 0:
            securitystrategy = DSecurityStrategy.query.filter_by(id=self.id, channelnumber=self.Param2, strategynumber=self.strategynumber).first()
            securitystrategy.SrcIP = self.dbSrcIP
            securitystrategy.SrcIPMask = self.dbSrcIPMask
            securitystrategy.DstIP = self.dbDstIP
            securitystrategy.DstIPMask = self.dbDstIPMask
            direction_dict = ['双向','正向','反向']
            protocol_dict = ['全部', 'ICMP', 'TCP', 'UDP']
            mode_dict = ['加密', '明文', '可选']
            try:
                securitystrategy.Direction = direction_dict[self.Direction]
            except:
                securitystrategys.Direction = '未知'
            try:
                securitystrategy.Protocol = protocol_dict[self.Protocol]
            except:
                securitystrategys.Protocol = '未知'
            try:
                securitystrategy.Mode = mode_dict[self.Mode]
            except:
                securitystrategys.Mode = '未知'
            securitystrategy.Reserved = self.Reserved

            securitystrategy.SrcPortMin = self.SrcPortMin
            securitystrategy.SrcPortMax = self.SrcPortMax
            securitystrategy.DstPortMin = self.DstPortMin
            securitystrategy.DstPortMax = self.DstPortMax
            db.session.add(securitystrategy)
            db.session.commit()
            db.session.close()
            #print 'Success!!!!!!!!!!!!!!'
        return  status
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

###############  Restart #############
class CRestartMachine():
    def __init__(self, id, dest_host, target    ):

        #self.src_host = GetHostIP()
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()

        # data of packet
        self.FunCode = 10
        self.Param1 = 0
        self.Param2 = 0
        #print self.channelnumber

        self.flag = 128
    def PackContent(self):

        buf = ctypes.create_string_buffer(16)  ###change the size 
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)

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
        #print 'status =', status
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
    
###############Log#############
class CQueryLogLength():
    def __init__(self, id,dest_host,  target    ):

        self.id = id
        self.dest_host = dest_host

        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 12
        self.Param1 = 0  #parameter 1
        self.Param2 = 0  #channel code
        self.flag = 128 # 0x80

        self.loglength = 0

    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.flag)
        return  buf.raw
    def PackPacket(self):

        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        Packet = snh + PacketHeader + PacketContent + confirmh

        return Packet

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
        content_receive = unpack('!BBH' , content_receive_pack)
        FunCode = content_receive[0]
        status = content_receive[1]
        Length = content_receive[2]
        if FunCode != self.FunCode:
            return None
        if status == 0:
            self.loglength = Length
            existrecord = models.DMachineLogLength.query.filter_by(id = self.id).first()
            if existrecord == None:
                newrecord = models.DMachineLogLength(self.id, Length)
                db.session.add(newrecord)
            else:
                existrecord.length = Length
                db.session.add(existrecord)
            db.session.commit()
        return status
    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn)
        if packet_receive == None: ## time out
            return [-2, self.loglength]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1, self.loglength]
        else:
            return [status, self.loglength]
####  Read Log###
class CReadLog():
    def __init__(self, id,dest_host, Parameter, target    ):
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 13
        self.Param1 = 0  #parameter 1
        self.recordnumber = Parameter[0]  #channel code
        self.startnumber = Parameter[1]
        self.flag = 128 # 0x80
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)
        content = struct.pack_into('!BBHLB', buf, 0, self.FunCode, self.Param1, self.recordnumber, self.startnumber, self.flag)
        return  buf.raw
    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        Packet = snh + PacketHeader + PacketContent + confirmh

        return Packet

    def  ParsePacket(self, packet_receive):
        try:
            ip_header = packet_receive[0:20]
            ip_protocol = unpack('!B',ip_header[9])[0]
            if ip_protocol != 254:
                return None
            snh = packet_receive[20:24]
            sn = unpack('!L', snh)[0]
            if sn != self.sn + 1:
                return None
        except:
            return None

        content_receive_head_pack = packet_receive[152:156]
        content_receive_head =  unpack('!BBH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        status = content_receive_head[1]
        recordnumber = content_receive_head[2]
        if FunCode != self.FunCode:
            return None   
        logs = []
        if status == 0:
            content_receive_data_pack = packet_receive[156:].split('\n')
            styles = ['人员操作', '系统信息', '通信信息']

            for index in range(recordnumber):
                recordlength = len(content_receive_data_pack[index])
                strtemp = '!' + str(recordlength) + 's'
                record = unpack(strtemp, content_receive_data_pack[index])[0]
		
                info = record.split()       
                if len(info) < 4 or len(record) > 256: 
                    continue
                time = info[0] + ' ' +info[1]
                try:
                    style = styles[int(info[2])]
                except:
                    style = '其他'
                try:
                    content = ' '.join(info[3:]).strip().decode('gbk')
                except:
                    content = "rmagent:"
                newrecord = models.DMachineLog(self.id, time, style, content)
                logs.append(newrecord)
        return [status,logs]                

    def  SendAndReceive(self):
        packet_send = self.PackPacket()
        packet_receive = Transport.SocketTransport(packet_send, self.dest_host, self.sn, Timeout = 12)
        if packet_receive == None: ## time out
            return [-2,[]]
        status = self.ParsePacket(packet_receive)
        if status == None:
            return [-1,[]]
        else:
            return status    
