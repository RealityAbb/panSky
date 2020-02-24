#!/usr/bin/env python
# coding=utf-8
from flask.ext.sqlalchemy import SQLAlchemy

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


#1.2.3 tian jia sui dao
class CAddChannel():
    def __init__(self, id, dest_host, parameters,  target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 77 #data lenth

        self.Command_Code = 6         #uchar
        self.IpAddr = parameters[0]    #uchar[32], ip address
        self.Work_Mode = parameters[1] #uchar, mode:invisible-0,selectable-1,visible-2
        self.vid = parameters[2]       #uchar[4], vlan id
        #self.vid = 2
        self.chname = parameters[3]    #uchar[21], channel name
        self.teamid = parameters[4]    #ulong[4], team id
        self.lino = parameters[5]  #uchar, line flag (0,1)
        ################  End #####################
        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(96)   ###change the size
        IpAddr = (self.IpAddr + '\x00' * 32)[:32]
        chname = (self.chname + '\x00' * 22)[:22]
        struct.pack_into('!BBHB32sB',buf, 0, self.FunCode, self.Param1, self.Param2, \
            self.Command_Code, IpAddr, self.Work_Mode)
        struct.pack_into('L',buf, 38, self.vid)
        struct.pack_into('!22sLLLLBB',buf, 42, chname, 0,0,0,0, self.lino, self.flag)
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
        snh = packet_receive[20:24]
        sn = unpack('!L', snh)[0]
        if sn != self.sn + 1:
            return None

        content_receive_head_pack = packet_receive[152:158]
        content_receive_head = unpack('!BBHBB' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code   
        Return_Code = content_receive_head[3]
        Status = content_receive_head[4]
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

#1.2.4 cha xun sui dao
class CQueryChannel():
    def __init__(self, id,dest_host,  target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1 #data lenth
        ### data
        self.Command_Code = 7  #uchar

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.flag)
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

        content_receive_head_pack = packet_receive[152:164]
        content_receive_head = unpack('!BBHBB2sL', content_receive_head_pack)
        FunCode = content_receive_head[0]
        if FunCode != self.FunCode:
            return None
        Param = content_receive_head[1]         #P=S
        Length = content_receive_head[2]        #L=Command_Code 
        Return_Code = content_receive_head[3]   #uchar
        Status = content_receive_head[4]        #uchar
        reserve = content_receive_head[5]       #uchar[2]                 
        if Status == 0:                          #if success, clear old
            BufferLen = content_receive_head[6]     #int

            channel_nums_receive = packet_receive[164:168]
            channel_nums = unpack('!L', channel_nums_receive)[0]
            existrecords = DPrivateChannelInfo.query.filter_by(id=self.id).all()
            dict = {}
            for existrecord in existrecords:
                dict.update({existrecord.channelnumber:existrecord})
            existrecordlist = dict.keys()
            for i in range(channel_nums):
                channel_result_receive = packet_receive[168 + 56 * i : 221 + 56 * i]
                channel_result = unpack('!16sHHBBH24sLB', channel_result_receive)
                Peer_Ip = channel_result[0].split('\x00')[0]
                Channel_ID = channel_result[1]
                Channel_ID_BAND = channel_result[2]
                Work_Mode_dict = ['密通', '可选','明通']
                try:
                    Work_Mode = Work_Mode_dict[channel_result[3]] #Encryption mode of channel
                except:
                    Work_Mode = '未知'             
                #Work_Mode = channel_result[3]
                Vlan_ID = channel_result[5]
                chname1 = channel_result[6].strip('\x00').split('\x00')[0]
                whichcode = whichEncode(chname1)
                if whichcode == 1:
                    chname = chname1
                elif whichcode == 2:
                    chname = chname1.decode('gbk').encode('utf-8')
                teamid = channel_result[7]
                lino = channel_result[8]
                if Channel_ID not in existrecordlist:
                    newrecord = DPrivateChannelInfo(self.id,Peer_Ip,Channel_ID, Channel_ID_BAND, Work_Mode, Vlan_ID, chname, teamid, lino)
                    db.session.add(newrecord)
                else:
                    record = dict[Channel_ID]
                    record.peer_addr = Peer_Ip
                    record.channelnumber_band = Channel_ID_BAND
                    record.work_model = Work_Mode
                    record.vlan_id = Vlan_ID
                    record.channelname = chname
                    record.teamid = teamid
                    record.lino = lino
                    db.session.add(record)
                    existrecordlist.remove(Channel_ID)
            for channel_id in existrecordlist:
                db.session.delete(dict[channel_id])
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

#1.2.5 liang tiao bang ding sui dao
class CBindChannel():
    def __init__(self, id, dest_host, parameters,  target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 #data lenth

        self.Command_Code = 8      #uchar
        self.Param = 0  #uchar, Param
        self.channel_id_1 = parameters[0]
        self.channel_id_2 = parameters[1]

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size
        #data = (self.data + '\x00' * 256)[:256]
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.Param)
        struct.pack_into('L',buf,6, self.channel_id_1)
        struct.pack_into('L',buf,10,self.channel_id_2)
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
        if Status == 0:
            record1 = DPrivateChannelInfo.query.filter_by(id=self.id,channelnumber=self.channel_id_1).first()
            record2 = DPrivateChannelInfo.query.filter_by(id=self.id,channelnumber=self.channel_id_2).first()
            if record1 == None or record2 == None:
                return -3
            record1.channelnumber_band = self.channel_id_2
            record2.channelnumber_band = self.channel_id_1
            db.session.add(record1)
            db.session.add(record2)
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

#1.2.9 shan chu sui dao
class CDeleteChannel():
    def __init__(self, id, dest_host, parameters,  target    ):   
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258 #data lenth

        self.Command_Code = 14    #uchar
        self.Param = 0 
        self.channel_id = parameters[0]  #uchar[256], word[0-3]:ChannelID

        self.flag = 128

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.Param)
        struct.pack_into('L',buf,6,self.channel_id)
        struct.pack_into('!B',buf,262,self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        #Packet = IPHeader + snh + PacketHeader + PacketContent + confirmh
        packet_send = snh + PacketHeader + PacketContent + confirmh
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
        if Status == 0:
            record = DPrivateChannelInfo.query.filter_by(id=self.id,channelnumber=self.channel_id).first()
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

#1.2.10 jie chu bang ding sui dao
class CRelieveBandChannel():
    def __init__(self, id, dest_host, parameters,  target    ):         
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        #data lenth
        self.Command_Code = 15    #uchar
        self.Param = 0 #uchar Param
        self.channel_id_1 = parameters[0]
        self.channel_id_2 = parameters[1]
        self.flag = 128

    def PackContent(self):
        buf = ctypes.create_string_buffer(272)
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.Param)
        struct.pack_into('L',buf,6, self.channel_id_1)
        struct.pack_into('L',buf,10,self.channel_id_2)
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
        
        #if len(packet_receive) < 156:   ##change the size according the packet
        #    return None 
        
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
            record1 = DPrivateChannelInfo.query.filter_by(id=self.id,channelnumber=self.channel_id_2).first()
            record2 = DPrivateChannelInfo.query.filter_by(id=self.id,channelnumber=self.channel_id_1).first()
            if record1 == None or record2 == None:
                return -3
            record1.channelnumber_band = 0
            record2.channelnumber_band = 0
            db.session.add(record1)
            db.session.add(record2)
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

#1.2.25 huoqusuidaoxinxiliebiao 
class CQueryChannelInfo():
    def __init__(self, id,dest_host,target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1
        self.Command_Code = 48
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.flag)
        
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
        #if Return_Code != self.Command_Code + 1:
        #   return None
        if Status == 0:
            allchannels = DPrivateChannelInfo.query.filter_by(id=self.id)
            existrecords = allchannels.all()
            existrecordlist = []
            recordlist = []
            for existrecord in existrecords:
                existrecordlist.append([existrecord.channelnumber, existrecord.lino])
            BufferLen = unpack('!L',packet_receive[160:164])[0]
            channel_nums = unpack('!L',packet_receive[164:168])[0]
            for i in range(channel_nums):
                '''channel_info_unpack = packet_receive[168 + 56 * i: 224 + 56 * i]
                channel_info = unpack('!21s4sHHHBBBBLLLLLB', channel_info_unpack)'''
                channel_info_unpack = packet_receive[168 + 72 * i: 227 + 72 * i]
                channel_info = unpack('!24s4sHHHBBBBLLLLLB', channel_info_unpack)

                chname = channel_info[0].strip('\x00').split('\x00')[0]#name of channel
                peer_addr = socket.inet_ntoa(channel_info[1])#IP 
                cid = channel_info[2]#channel No
                cid1 = channel_info[3]#channel No of the same group channel,0-unknown
                channel_mode_dict = ['加密', '可选', ' 明通 ']
                try:
                    channel_mode = channel_mode_dict[channel_info[4]] #Encryption mode of channel
                except:
                    channel_mode = '未知'
                neg_status_dict = ['初始','请求已发送','响应以发送','开启']
                try:
                    neg_status = neg_status_dict[channel_info[5]]#negotiation state
                except:
                    neg_status = '未知'
                policy_num = channel_info[6]#policy number
                peer_prior_dict = ['备机', '主机']
                try:
                    peer_prior = peer_prior_dict[channel_info[7]]#1-host 0-preparation
                except:
                    peer_prior = '未知'
                peer_state_dict = ['不工作','工作']
                try:
                    peer_state = peer_state_dict[channel_info[8]]
                except:
                    peer_state = '未知'
                timegap = channel_info[9]
                last_neg_success = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timegap))                    
                neg_packets_sent = channel_info[10]
                neg_packets_recv = channel_info[11]
                neg_packets_err = channel_info[12]
                teamid = channel_info[13]#ID of channel group
                lino = channel_info[14]#link No
                record = allchannels.filter_by(channelnumber=cid,lino=lino).first()
                recordlist.append([cid,lino])
                if [cid,lino] not in existrecordlist:
                    newrecord = DPrivateChannelInfo(self.id,peer_addr,cid,cid1,channel_mode,None,chname, teamid,lino, neg_status, policy_num, peer_prior, peer_state,last_neg_success,neg_packets_sent, neg_packets_recv, neg_packets_err)
                    db.session.add(newrecord)
                else:
                    #record.channelname = chname
                    record.channelname = chname
                    record.peer_addr = peer_addr
                    record.channelnumber = cid
                    record.channelnumber_band = cid1
                    record.work_model = channel_mode
                    #record.vlan_id = vlan_id
                    record.neg_status = neg_status
                    record.policy_num = policy_num
                    record.peer_prior = peer_prior
                    record.peer_state = peer_state
                    record.last_neg_successtime = last_neg_success
                    #print last_neg_success
                    record.neg_packets_sent = neg_packets_sent
                    record.neg_packets_recv = neg_packets_recv
                    record.neg_packets_err = neg_packets_err
                    record.teamid = teamid
                    #print record.last_neg_successtime
                    record.lino = lino
                    db.session.add(record)
                    db.session.commit()
                    #print "existrecord#####################"
            db.session.commit()
            for existrecord in existrecords:
                if [existrecord.channelnumber,existrecord.lino] not in recordlist:
                    db.session.delete(existrecord)
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

#1.2.26 fasongtanceqingqiu 
class CSendDetectRequest():
    def __init__(self, id,dest_host, parameters,target    ):   
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 5
        self.Command_Code = 49
        self.channel_id = parameters[0]#channel ID

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBLB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.channel_id,self.flag)
        
        return  buf.raw
    def PackPacket(self):
        
        #sn = GenerateSN()
        snh = struct.pack("!L", self.sn)
        PacketHeader = GeneratePacketHeader(self.target, self.dest_host)
        PacketContent = self.PackContent()
        confirmh = Confirm()
        #Packet = IPHeader + snh + PacketHeader + PacketContent + confirmh
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


#1.2.37
class SetMasterMasterChannel():
    def __init__(self, id,dest_host, parameters,target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 73
        self.model = parameters[0]#int
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        content = struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.model)
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
        #Param = content_receive_head_pack[]
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
                dict = {'master_master_channel':bool(self.model)}
                newrecord = DPrivateEquipmentCommonInfo(self.id, dict)
                db.session.add(newrecord)
            else:
                record.master_master_channel = bool(self.model)
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
            
###########1.2.41
class CRenameChannel():
    def __init__(self, id,dest_host,parameters,target    ):   

        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 80
        self.Param = 0
        self.channelnumber = parameters[0]
        self.newname = parameters[1]
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        newname = (self.newname + '\x00' * 20)[:20]
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.Param)
        struct.pack_into('L', buf,6,self.channelnumber)
        struct.pack_into('!20s',buf,10,newname)
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
        #Param = content_receive_head_pack[]
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            record = DPrivateChannelInfo.query.filter_by(id=self.id, channelnumber=self.channelnumber).first()
            if record == None:
                return None
            record.channelname = self.newname.decode('gbk').encode('utf-8')
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

#1.2.42
class CBindChannelTeam():
    def __init__(self, id,dest_host,parameters,target    ):   
    
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 81
        self.Param = 0
        self.channelcount = parameters[0]#int
        self.teamid = parameters[1]
        self.channelnumbers = parameters[2:]       
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.Param)
        struct.pack_into('L',buf, 6, self.channelcount)
        struct.pack_into('L',buf,10, self.teamid)
        for index,channelnumber in enumerate(self.channelnumbers):
            struct.pack_into('L',buf,14 + 4 * index,channelnumber)
        struct.pack_into('!B',buf, 262, self.flag)
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
        #Param = content_receive_head_pack[]
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        #Status = 0
        if Status == 0:
            for channelnumber in self.channelnumbers:
                record = DPrivateChannelInfo.query.filter_by(id=self.id, channelnumber=channelnumber).first()
                if record == None:
                    continue
                record.teamid = self.teamid
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

class CResetChannel():
    def __init__(self, id,dest_host,parameters,target    ):
        #self.src_host = socket.gethostbyname(socket.gethostname())
        #self.src_host = GetHostIP()
        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        # the
        self.FunCode = 11
        self.Param1 = 0  #parameter 1
        self.Param2 = parameters[0]  #channel code
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
        #print repr(content_receive_pack)
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