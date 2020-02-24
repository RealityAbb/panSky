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
             
#1.2.16 shezhidanshuangjimoshi
class CSetStandAlone():
    def __init__(self, id,dest_host,parameters,target    ):   

        self.id = id
        self.dest_host = dest_host
        #self.dest_port = dest_port
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 2
        self.Command_Code = 28
        self.onlyone = parameters[0]#1-single mechine  0-double mechine
        self.flag = 128
    def PackContent(self):
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.onlyone,self.flag)
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

        ################# Change From Here #################
        content_receive_head_pack = packet_receive[152:156]
        content_receive_head = unpack('!BBH' , content_receive_head_pack)
        FunCode = content_receive_head[0]
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            isstandalone = unpack('!B', packet_receive[160])[0]
            if isstandalone != self.onlyone:
                return None
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'isstandalone':bool(isstandalone)}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.isstandalone = bool(isstandalone)
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
               
#1.2.17 shezhizhubeimoshi
class CSetMasterModel():
    def __init__(self, id,dest_host,parameters,target    ):   
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 2
        self.Command_Code = 29
        self.masterdev = parameters[0]#1-host 0-preparation

        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code,self.masterdev,self.flag)
        
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
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None
        if Status == 0:
            ismaster = unpack('!B', packet_receive[160])[0]
            if ismaster != self.masterdev:
                return None
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'ismaster':bool(self.masterdev)}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.ismaster = bool(self.masterdev)
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

#1.2.31 zhi xing ming ling
class CExecuteCommand():
    def __init__(self,id,dest_host,parameters,target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 58
        self.command = parameters[0] #string/command
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size
        struct.pack_into('!BBHB',buf,0,self.FunCode, self.Param1, self.Param2,self.Command_Code)
        struct.pack_into( '!' + str(len(self.data)) + 's', buf,6,self.command)
        struct.pack_into('!B', buf,262,self.flag)
        
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

#1.2.31 huo qu ming ling zhi xing jie guo            
class CGetCommandResult():
    def __init__(self, id,dest_host,parameters,target    ):   
    
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 6
        self.Command_Code = 40
        self.File_Type = 3 
        self.Offset = parameters[0] #string
        
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(16)   ###change the size 
        content = struct.pack_into('!BBHBB4sB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code, self.File_Type, self.Offset, self.flag)
        
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
            content_receive_data_pack = packet_receive[160:163]      
            content_receive_data = unpack('!BH', content_receive_data_pack)
            Flag = content_receive_data[0]
            Data_Len = content_receive_data[1]#return content length
            
            Data = unpack('!' + str(Data_Len) + 's',packet_receive[16])[0]
            path = os.path.join('tmp','commandresult.txt')
            file = open(path,'w')
            file.write(Data)
            file.close()
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


#1.2.43
class CGetStatisticsCount():
    def __init__(self, id,dest_host,target    ):   

        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 82
       
        self.flag = 128
    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHB', buf, 0, self.FunCode, self.Param1, self.Param2, self.Command_Code)
        
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
            content_receive_io_statist_struct_pack = packet_receive[160:180]      
            content_receive_io_statist_struct = unpack('!LLLLL', content_receive_io_statist_struct_pack)
            enc_packets = content_receive_io_statist_struct[0]
            dec_packets = content_receive_io_statist_struct[1]
            enc_errors = content_receive_io_statist_struct[2]
            dec_errors = content_receive_io_statist_struct[3]
            packets_total = content_receive_io_statist_struct[4]
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            dict = {'enc_packets':enc_packets,'dec_packets':dec_packets,'enc_errors':enc_errors,'dec_errors':dec_errors,'packets_total':packets_total}
            if record == None:
                newrecord =  DPrivateEquipmentCommonInfo(self.id,dict) # Create a new record, the DataBaseName is given by yourselves
                db.session.add(newrecord) ### add the newrecord to the database
            else:
                record.Modify(dict)
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

#1.2.44
class CGetParameterInformation():
    def __init__(self, id,dest_host,  target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1
        self.Command_Code = 86

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

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None


        if Status == 0:    
            content_receive_data_pack = packet_receive[160:260]
            content_receive_data = unpack('!50s50s',content_receive_data_pack)
            equipment_id = content_receive_data[0].strip('\x00').split('\x00')[0]
            equipment_info = content_receive_data[1].strip('\x00').split('\x00')[0]
            dict = {'equipment_id':equipment_id, 'equipment_info':equipment_info}
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                newrecord =  DPrivateEquipmentCommonInfo(self.id,dict) # Create a new record, the DataBaseName is given by yourselves
                db.session.add(newrecord) ### add the newrecord to the database
            else:
                record.Modify(dict)
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

#1.2.15 1.2.49       
class CQuerySystemInfo():
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()
        
        self.lino = parameters[0]
        # data of packet
        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 1 #parameter1 the length of data
        if self.lino == 0:
            self.Command_Code = 27
        else:
            self.Command_Code = 91

        self.flag = 128 #0x80

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

    def  ParsePacket(self, packet_receive):
        ip_header = packet_receive[0:20]
        ip_protocol = unpack('!B',ip_header[9])[0]
        if ip_protocol != 254:
            return None
        snh=packet_receive[20:24]
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
            #print repr(packet_receive)
            system_config_1 = unpack('!BBBB' , packet_receive[160:164])  ## common info
            work_model = system_config_1[0]
            ncard = system_config_1[1]
            work_status = system_config_1[2]
            firewall = system_config_1[3]
            
            system_config_2 = unpack('!LLBBB',packet_receive[164:175]) #common info
            dk_lifetime = int(system_config_2[0] / 3600)
            dk_encrypt_times_max = int(system_config_2[1] / 10000)
            dk_retry_interval = system_config_2[2]
            rm_errors_can_tolerance = system_config_2[3]
            rm_block_request_time = system_config_2[4]
            
            system_config_3 = unpack('!BBBBB',packet_receive[175:180]) # common info
            #print repr(packet_receive[172:180])
            cert_format = system_config_3[0]
            debug = system_config_3[1]
            compress = system_config_3[2]
            isstandalone = bool(system_config_3[3])
            ismaster = bool(system_config_3[4])
            
            system_config_4 = unpack('!BL3sHHBBH',packet_receive[180:196])
            #print 'stp_state = ', system_config_4[0]
            stp_state = bool(system_config_4[0])
            stp_prio = system_config_4[1]  ## common  info
            syn_timeout1 = system_config_4[3]   ## common info
            syn_timeout2 = system_config_4[4]   ## common info
            twin_active = system_config_4[5] 
            #print 'no_alarm = ', system_config_4[6]
            no_alarm = bool(system_config_4[6])       ## common info
            change_time = system_config_4[7]    ## common info

            system_config_5 = unpack('!4s4s4s4s',packet_receive[196:212]) ### link info
            ipaddr = socket.inet_ntoa(system_config_5[0])
            ipmask = socket.inet_ntoa(system_config_5[1])
            twin_addr = socket.inet_ntoa(system_config_5[2])
            man_nic_addr = socket.inet_ntoa(system_config_5[3])

            route_num = unpack('!L',packet_receive[212:216])[0]
            route_table = packet_receive[216:1048]       
            existrecords = DRouteTable.query.filter_by(id=self.id,lino=self.lino).all()
            existlen = len(existrecords)
            if route_num == 0:
                for i in range(0,existlen):
                    db.session.delete(existrecords[i])
            else:                    
                for index in range(route_num):
                    route_receive_pack = route_table[52 * index : 52 + 52 * index]
                    route_receive = unpack('16s16s16si', route_receive_pack)
                    route_ipaddr = route_receive[0].strip('\x00').split('\x00')[0]
                    netmask = route_receive[1].strip('\x00').split('\x00')[0]
                    gateway = route_receive[2].strip('\x00').split('\x00')[0]
                    print "###### route_type ###### = ",route_receive[3]
                    type_dict = ["网络路由","主机路由","默认路由"]
                    try:
                        routetype = type_dict[route_receive[3]]
                    except:
                        routetype = "未知"
                    if index < existlen:
                        record = existrecords[index]
                        record.routenumber = index + 1
                        record.ipaddr = route_ipaddr
                        record.netmask = netmask
                        record.gateway = gateway
                        record.type = routetype
                        db.session.add(record)
                    else:
                        newrecord = DRouteTable(self.id,self.lino,index + 1,route_ipaddr, netmask, gateway, routetype)
                        db.session.add(newrecord)
                for i in range(route_num,existlen):
                    db.session.delete(existrecords[i])
            ########### Route Tabel ############
            
            system_config_6 = unpack('!BL',packet_receive[1048:1053]) #### common info
            nic_num = system_config_6[0]
            max_log_size = system_config_6[1]
            
            system_config_7 = unpack('!BBB',packet_receive[1056:1059]) ### link info
            virtual_ip_enabled = bool(system_config_7[0])
            vlan_trunk_enabled = bool(system_config_7[1])
            vlan_bind_channel = bool(system_config_7[2])
            
            system_config_8 = unpack('!BBB',packet_receive[1059:1062]) ### common info
            master_master_channel = bool(system_config_8[0])
            sping_send_interval = system_config_8[1]
            sping_response_timeout = system_config_8[2]
            
            system_config_9 = unpack('!BBBBHBB',packet_receive[1062:1070])
            post_fragment_enabled = bool(system_config_9[0])
            global_forward_policy = bool(system_config_9[1])
            this_host_reachability = bool(system_config_9[2])
            line_work_enable = bool(system_config_9[3])
            default_vid = system_config_9[4]
            one_ip_hotswap = bool(system_config_9[5])
            multi_ip = bool(system_config_9[6])
            
            softbypass = unpack('!B',packet_receive[1070])[0]
            
            dict_common = {'work_model':work_model,'ncard':ncard,'work_status':work_status,'firewall':firewall,'dk_lifetime':dk_lifetime, \
            'dk_encrypt_times_max':dk_encrypt_times_max,'dk_retry_interval':dk_retry_interval,'rm_error_can_tolerance':rm_errors_can_tolerance, \
            'rm_block_request_time':rm_block_request_time,'cert_format':cert_format,'debug':debug,'compress':compress, \
            'isstandalone':isstandalone,'ismaster':ismaster,'stp_prio':stp_prio,'syn_timeout1':syn_timeout1,'syn_timeout2':syn_timeout2, \
            'no_alarm':no_alarm, 'change_time':change_time,'nic_num':nic_num,'max_log_size':max_log_size,'master_master_channel':master_master_channel,\
            'sping_send_interval':sping_send_interval,'sping_response_timeout':sping_response_timeout, \
            'this_host_reachability':this_host_reachability, 'one_ip_hotswap':one_ip_hotswap, 'softbypass':softbypass}
            
            dict_link = {'stp_state':stp_state,'twin_active':twin_active,'ipaddr':ipaddr,'ipmask':ipmask,'twin_addr':twin_addr, \
            'man_nic_addr':man_nic_addr,'virtual_ip_enabled':virtual_ip_enabled,'vlan_trunk_enabled':vlan_trunk_enabled, \
            'vlan_bind_channel':vlan_bind_channel,'post_fragment_enabled':post_fragment_enabled,'global_forward_policy':global_forward_policy, \
           'line_work_enable':line_work_enable, 'default_vid':default_vid,\
            'multi_ip':multi_ip}
            if self.lino == 0:
                record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
                if record == None:
                    newrecord = DPrivateEquipmentCommonInfo(self.id,dict_common)
                    db.session.add(newrecord)
                else:
                    record.Modify(dict_common)
                    db.session.add(record)
            record_link = DPrivateEquipmentLinkInfo.query.filter_by(id=self.id,lino=self.lino).first()
            if record_link ==None:
                newrecord_link = DPrivateEquipmentLinkInfo(self.id,self.lino,dict_link)
                db.session.add(newrecord_link)
            else:
                record_link.Modify(dict_link)
                db.session.add(record_link)
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
        
#1.2.53            
class CEnableDoubleMachine():
    def __init__(self, id,dest_host, parameters, target    ):   
        self.id = id
        self.dest_host = dest_host
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 95
        self.Param = 0
        self.data0 = parameters[0] #data[0] =1

        self.flag = 128 #0x80

    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size 
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.Param,self.data0)
        #struct.pack_into('!'+str(len(self.data))+'s',buf,6,self.data)
        struct.pack_into('!B',buf,262,self.flag)
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
            record = DPrivateEquipmentCommonInfo.query.filter_by(id=self.id).first()
            if record == None:
                dict = {'one_ip_hotswap':bool(self.data0)}
                newrecord = DPrivateEquipmentCommonInfo(self.id,dict)
                db.session.add(newrecord)
            else:
                record.one_ip_hotswap = bool(self.data0)
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

#1.2.62            
class CPingTest():
    def __init__(self, id,dest_host, parameters, target    ):   
        
        self.id = id
        self.dest_host = dest_host
        
        self.target = target
        self.sn = GenerateSN()

        self.FunCode = 254
        self.Param1 = 254
        self.Param2 = 258
        self.Command_Code = 105
        self.Param = 0
        self.ping_ip = parameters[0]

        self.flag = 128 #0x80


    def PackContent(self):
         
        buf = ctypes.create_string_buffer(272)   ###change the size
        ping_ip = socket.inet_aton(self.ping_ip)
        struct.pack_into('!BBHBBB', buf, 0, self.FunCode, self.Param1, self.Param2,self.Command_Code,self.Param,ping_ip)
        struct.pack_into('!B',buf,262,self.flag)
        #############    End   ##############
        return  buf.raw

    def PackPacket(self):
        IPHeader = GenerateIPHeader(self.src_host, self.dest_host)
        #sn = GenerateSN()
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
        #Param = content_receive_head_pack[]
        Param = content_receive_head[1]    #P=S
        Length = content_receive_head[2]   #L=Command_Code

        content_receive_general_resp = unpack('!BB' , packet_receive[156:158])
        Return_Code = content_receive_general_resp[0]
        Status = content_receive_general_resp[1]
        if Return_Code != self.Command_Code + 1:
            return None           
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
      