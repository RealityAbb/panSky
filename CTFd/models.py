#!/usr/bin/env python
# coding=utf-8
from flask_sqlalchemy import SQLAlchemy

from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from passlib.hash import bcrypt_sha256

import datetime
import hashlib
import time
import urlparse

def sha512(string):
    return hashlib.sha512(string).hexdigest()

def ip2long(ip):
    return unpack('!I', inet_aton(ip))[0]

def long2ip(ip_int):
    return inet_ntoa(pack('!I', ip_int))

db = SQLAlchemy(use_native_unicode="utf8")

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32),unique=True)
    admin = db.Column(db.Integer)
    password = db.Column(db.String(32))
    ukeyid = db.Column(db.String(32))
    ukeycert = db.Column(db.String(32))
    style = db.Column(db.Integer)
    pk = db.Column(db.Unicode(64))
    losesign = db.Column(db.Boolean,default=True)


    def __init__(self, name, admin, password, ukeyid, ukeycert, style, pk, losesign):
        self.name = name
        self.admin = admin
        self.password = password
        self.ukeyid = ukeyid
        self.ukeycert = ukeycert
        self.style = style
        self.pk = pk
        self.losesign = losesign
        
    def __repr__(self):
        return '<user %r>' % self.name

class SystemRoutes(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	gateway = db.Column(db.String(128))
	style = db.Column(db.String(128))

	def __init__(self, gateway, style):
		self.gateway = gateway
		self.style = style

class SysIPAddress(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	ip = db.Column(db.String(128),unique=True)

	def __init__(self, ip):
		self.ip = ip

class Certificates(db.Model):
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    certname = db.Column(db.String(64))
    
    def __init__(self, id, certname):
        self.id = id
        self.certname = certname

class UploadCertificates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    certname = db.Column(db.String(64))

    def __init__(self,certname):
        self.id = id
        self.certname = certname


class CertDetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.Integer)
    uuid = db.Column(db.String(128))
    algorithm = db.Column(db.String(128))
    issuer = db.Column(db.String(128))
    starttime = db.Column(db.Float)
    endtime= db.Column(db.Float)
    theme = db.Column(db.String(128))

    def __init__(self, version, uuid, algorithm, issuer, starttime, endtime, theme):
        self.version = version
        self.uuid = uuid
        self.algorithm = algorithm
        self.issuer = issuer
        self.starttime = starttime
        self.endtime = endtime
        self.theme = theme

class Tree(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    province = db.Column(db.String(128))
    city = db.Column(db.String(128))
    part = db.Column(db.String(128))
    fourth = db.Column(db.String(128))

    def __init__(self,province,city,part,fourth):
        self.province = province
        self.city = city
        self.part = part
        self.fourth = fourth


class Cipermachine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(128),unique=True)
    machinenumber = db.Column(db.String(128))
    province = db.Column(db.String(128))
    city = db.Column(db.String(128))
    part = db.Column(db.String(128))
    fourth = db.Column(db.String(128))
    manufacture = db.Column(db.String(128))
    isonline = db.Column(db.Boolean)
    spingtime = db.Column(db.Integer)
    discription = db.Column(db.String(128))
    encrypttype = db.Column(db.SmallInteger)
    def __init__(self, ip, machinenumber, province, city, part, fourth, manufacture, isonline, spingtime, discription, encrypttype = 0):
        self.ip = ip
        self.machinenumber = machinenumber
        self.province = province
        self.city = city
        self.part = part
        self.fourth = fourth
        self.manufacture = manufacture
        self.isonline = isonline
        self.spingtime = spingtime
        self.discription = discription
        self.encrypttype = encrypttype

class Terminallogs(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	rank = db.Column(db.String(128))
	time = db.Column(db.Float)
	name = db.Column(db.String(128))
	style = db.Column(db.String(128))
	content = db.Column(db.String(128))

	def __init__(self, rank, time, name, style, content):
		self.rank=rank
		self.time=time
		self.name=name
		self.style=style
		self.content=content

	def __repr__(self):
		return self.id

class LeadMachinelogs(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	rank = db.Column(db.String(128))
	time = db.Column(db.Float)
	name = db.Column(db.String(128))
	style = db.Column(db.String(128))
	content = db.Column(db.String(128))

	def __init__(self, rank, time, name, style, content):
		self.rank=rank
		self.time=time
		self.name=name
		self.style=style
		self.content=content

	def __repr__(self):
		return self.id

class EquipmentsStatus(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	status = db.Column(db.Integer)
	workmodel = db.Column(db.Integer)
	sign = db.Column(db.Integer)
	restain = db.Column(db.Integer)
	encrypt = db.Column(db.Integer)
	decrypt = db.Column(db.Integer)
	errorencrypt = db.Column(db.Integer)
	errordecrypt = db.Column(db.Integer)
	send = db.Column(db.Integer)
	receive = db.Column(db.Integer)
	errorreceive = db.Column(db.Integer)

	def __init__(self, id,status, workmodel, sign, restain, encrypt, decrypt, errorencrypt, errordecrypt, send, receive, errorreceive):
		self.id = id
		self.status = status
		self.workmodel = workmodel
		self.sign = sign
		self.restain = restain
		self.encrypt = encrypt
		self.decrypt = decrypt
		self.errorencrypt = errorencrypt
		self.errordecrypt = errordecrypt
		self.send = send
		self.receive = receive
		self.errorreceive = errorreceive

class ChannelNumber(db.Model):
	keyid = db.Column(db.Integer,primary_key=True)
	id = db.Column(db.Integer)
	channelnumber = db.Column(db.Integer)
	def __init__(self, id, number):
		self.id =  id
		self.channelnumber = number

class ChannelStatus(db.Model):
    keyid = db.Column(db.Integer,primary_key=True)
    id = db.Column(db.Integer)
    channelnumber = db.Column(db.Integer)
    uip = db.Column(db.String(128))
    mode = db.Column(db.Integer)
    mainsub = db.Column(db.Integer)
    strategy = db.Column(db.Integer)
    negostatus = db.Column(db.Integer)
    successtime = db.Column(db.String(128))
    encrypt = db.Column(db.Integer)
    decrypt = db.Column(db.Integer)
    errorencrypt = db.Column(db.Integer)
    errordecrypt = db.Column(db.Integer)
    send = db.Column(db.Integer)
    receive = db.Column(db.Integer)
    errorreceive = db.Column(db.Integer)

    def __init__(self, id, channelnumber, uip=None, mode=None, mainsub=None, strategy=None, negostatus=None, successtime=None, encrypt=None, decrypt=None, errorencrypt=None, errordecrypt=None, send=None, receive=None, errorreceive=None):
        self.id = id
        self.channelnumber = channelnumber
        self.uip = uip
        self.mode = mode
        self.mainsub = mainsub
        self.strategy = strategy
        self.negostatus = negostatus
        self.successtime = successtime
        self.encrypt = encrypt
        self.decrypt = decrypt
        self.errorencrypt = errorencrypt
        self.errordecrypt = errordecrypt
        self.send = send
        self.receive = receive
        self.errorreceive= errorreceive

# class Config(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     key = db.Column(db.Text)
#     value = db.Column(db.Text)

#     def __init__(self, key, value):
#         self.key = key
#         self.value = value

class DStandarCertificate(db.Model):
    keyid = db.Column(db.Integer, primary_key=True)
    machineid = db.Column(db.Integer)
    certname = db.Column(db.String(64))
    
    def __init__(self, machineid, certname):
        self.machineid = machineid
        self.certname = certname

class DSecurityStrategy(db.Model):
    __tablename__ = 'channel_security_strategy'
    keyid = db.Column(db.Integer,primary_key=True)

    id = db.Column(db.Integer)
    channelnumber = db.Column(db.Integer)
    strategynumber = db.Column(db.Integer)

    SrcIP = db.Column(db.String(128))
    SrcIPMask = db.Column(db.String(128))
    DstIP = db.Column(db.String(128))
    DstIPMask = db.Column(db.String(128))

    Direction = db.Column(db.String(128))
    Protocol = db.Column(db.String(128))
    Mode = db.Column(db.String(128))
    Reserved = db.Column(db.Integer)

    SrcPortMin = db.Column(db.Integer)
    SrcPortMax = db.Column(db.Integer)
    DstPortMin = db.Column(db.Integer)
    DstPortMax = db.Column(db.Integer)
    def __init__(self, id, channelnumber,strategynumber, SrcIP, SrcIPMask, DstIP,DstIPMask, Direction, Protocol, Mode, Reserved, SrcPortMin, SrcPortMax, DstPortMin,DstPortMax):
        
        self.id = id
        self.channelnumber = channelnumber
        self.strategynumber = strategynumber

        self.SrcIP = SrcIP
        self.SrcIPMask = SrcIPMask
        self.DstIP = DstIP
        self.DstIPMask = DstIPMask

        self.Direction = Direction
        self.Protocol = Protocol
        self.Mode = Mode
        self.Reserved = Reserved

        self.SrcPortMin = SrcPortMin
        self.SrcPortMax = SrcPortMax
        self.DstPortMin = DstPortMin
        self.DstPortMax = DstPortMax

class DMachineLogLength(db.Model):
    __tablename__ = "machine_loglengths"
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    length = db.Column(db.Integer)
    def __init__(self, id, length):
        self.id = id
        self.length = length
        
class DMachineLog(db.Model):
    __tablename__ = "machine_logs"
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    time = db.Column(db.String(128))
    style = db.Column(db.String(128))
    content = db.Column(db.String(256))

    def __init__(self, id, time, style, content):
        self.id = id
        self.time = time
        self.style = style
        self.content = content

class DPrivateEquipmentCommonInfo(db.Model):
    __tablename__ = "prinvate_equipment_common_info"
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    work_model = db.Column(db.SmallInteger)
    ncard = db.Column(db.SmallInteger)
    work_status = db.Column(db.SmallInteger)
    firewall = db.Column(db.Boolean)
    dk_lifetime = db.Column(db.Integer)
    dk_encrypt_times_max = db.Column(db.Integer)
    dk_retry_interval = db.Column(db.SmallInteger)
    rm_error_can_tolerance = db.Column(db.SmallInteger)
    rm_block_request_time = db.Column(db.SmallInteger)
    cert_format = db.Column(db.SmallInteger)
    debug = db.Column(db.SmallInteger)
    compress = db.Column(db.SmallInteger)
    isstandalone = db.Column(db.Boolean)
    ismaster = db.Column(db.Boolean)
    stp_prio = db.Column(db.Integer) ## using to shuang ji hu bei
    syn_timeout1 = db.Column(db.Integer)
    syn_timeout2 = db.Column(db.Integer)
    no_alarm = db.Column(db.Boolean)
    change_time = db.Column(db.SmallInteger) # using to local access
    nic_num = db.Column(db.SmallInteger)
    max_log_size = db.Column(db.Integer)
    master_master_channel = db.Column(db.Boolean)
    sping_send_interval = db.Column(db.Integer)
    sping_response_timeout = db.Column(db.Integer)
    this_host_reachability = db.Column(db.Boolean)
    one_ip_hotswap = db.Column(db.Boolean)
    softbypass = db.Column(db.Boolean)
    ###1.2.43
    enc_packets = db.Column(db.Integer)
    dec_packets = db.Column(db.Integer)
    enc_errors = db.Column(db.Integer)
    dec_errors = db.Column(db.Integer)
    packets_total = db.Column(db.Integer)
    
    ### 1.2.44
    equipment_id = db.Column(db.String(64))
    equipment_info = db.Column(db.String(64))
    ### 1.2.53
    ##masterchange = db.Column(db.Boolean)   
    ### 1.1.57 1.2.58 IPSec
    ipsec_parameter = db.Column(db.String(256))
    
    ### 1.1.59 1.2.60 plateform state
    secplateformflag = db.Column(db.Boolean)
    def __init__(self,id, category_dict):
        self.id = id
        self.work_model = None
        self.ncard = None
        self.work_status = None
        self.firewall = None
        self.dk_lifetime = None
        self.dk_encrypt_times_max = None
        self.dk_retry_interval = None
        self.rm_error_can_tolerance = None
        self.rm_block_request_time = None
        self.cert_format = None
        self.debug = None
        self.compress = None
        self.isstandalone = None
        self.ismaster = None
        self.stp_prio = None ## using to shuang ji hu bei
        self.syn_timeout1 = None
        self.syn_timeout2 = None
        self.no_alarm = None
        self.change_time = None # using to local access
        self.nic_num = None
        self.max_log_size = None
        self.master_master_channel = None
        self.sping_send_interval = None
        self.sping_response_timeout = None
        self.this_host_reachability = None
        self.one_ip_hotswap = None
        self.softbypass = None
        ## 1.2.43 
        self.enc_packets = None
        self.dec_packets = None
        self.enc_errors = None
        self.dec_errors = None
        self.packets_total = None 
        ## 1.2.44        
        self.equipment_id = None
        self.equipment_info = None

        ##1.2.53
        #self.masterchange = False

        ## 1.2.55 1.2.57 IPSec
        self.ipsec_parameter = None
        ### 1.2.59 1.2.60
        self.secplateformflag = None
        
        
        self.Modify(category_dict)

        

    def Modify(self, category_dict):
        category_keys = category_dict.keys()
        for category_key in category_keys:
            category_value = category_dict[category_key]
            if category_key == 'work_model':
                self.work_model = category_value

            elif category_key == 'ncard':
                self.ncard = category_value
            elif category_key == 'work_status':
                self.work_status = category_value
            elif category_key == 'firewall':
                self.firewall = category_value
            elif category_key == 'dk_lifetime':
                self.dk_lifetime = category_value
            elif category_key == 'dk_encrypt_times_max':
                self.dk_encrypt_times_max = category_value
            elif category_key == 'dk_retry_interval':
                self.dk_retry_interval = category_value
            elif category_key == 'rm_error_can_tolerance':
                self.rm_error_can_tolerance = category_value
            elif category_key == 'rm_block_request_time':
                self.rm_block_request_time = category_value
            elif category_key == 'cert_format':
                self.cert_format = category_value
            elif category_key == 'debug':
                self.debug = category_value
            elif category_key == 'compress':
                self.compress = category_value
            elif category_key == 'isstandalone':
                self.isstandalone = category_value                
            elif category_key == 'ismaster':
                self.ismaster = category_value
            elif category_key == 'stp_prio':
                self.stp_prio = category_value
            elif category_key == 'syn_timeout1':
                self.syn_timeout1 = category_value
            elif category_key == 'syn_timeout2':
                self.syn_timeout2 = category_value                
            elif category_key == 'no_alarm':
                self.no_alarm = category_value
            elif category_key == 'change_time':
                self.change_time = category_value
            elif category_key == 'nic_num':
                self.nic_num = category_value
            elif category_key == 'max_log_size':
                self.max_log_size = category_value
            elif category_key == 'master_master_channel':
                self.master_master_channel = category_value
            elif category_key == 'sping_send_interval':
                self.sping_send_interval = category_value
            elif category_key == 'sping_response_timeout':
                self.sping_response_timeout = category_value
            elif category_key == 'this_host_reachability':
                self.this_host_reachability = category_value
            elif category_key == 'one_ip_hotswap':  ### 1.2.53
                self.one_ip_hotswap = category_value
            elif category_key == 'softbypass':
                self.softbypass = category_value
            ## 1.2.43
            elif category_key == 'enc_packets':
                self.enc_packets = category_value                
            elif category_key == 'dec_packets':
                self.dec_packets = category_value                
            elif category_key == 'enc_errors':
                self.enc_errors = category_value                
            elif category_key == 'dec_errors':
                self.dec_errors = category_value                
            elif category_key == 'packets_total':
                self.packets_total = category_value  
            ## 1.2.44
            elif category_key == 'equipment_id':
                self.equipment_id = category_value
            elif category_key == 'equipment_info':
                self.equipment_info = category_value

            # ## 1.2.53
            # elif category_key == "masterchange":
            #     masterchange = category_value

            ## 1.2.57 1.2.58 IPSec
            elif category_key == 'ipsec_parameter':
                self.ipsec_parameter = category_value
            ## 1.2.59 1.2.60
            elif category_key == 'secplateformflag':
                self.secplateformflag = category_value
class DPrivateEquipmentLinkInfo(db.Model):                
    __tablename__ = "private_equipment_link_info"
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    lino = db.Column(db.SmallInteger)
    stp_state = db.Column(db.Boolean)
    #syn_timeout = db.Column(db.SmallInteger)
    twin_active = db.Column(db.SmallInteger) # using to global_forward_policy
    ipaddr = db.Column(db.String(32))
    ipmask = db.Column(db.String(32))
    twin_addr = db.Column(db.String(32))
    man_nic_addr = db.Column(db.String(32))    
    virtual_ip_enabled = db.Column(db.Boolean)
    vlan_trunk_enabled = db.Column(db.Boolean)
    vlan_bind_channel = db.Column(db.Boolean)
    post_fragment_enabled = db.Column(db.Boolean)
    global_forward_policy = db.Column(db.Boolean)
    line_work_enable = db.Column(db.Boolean)
    default_vid = db.Column(db.Integer)
    #one_ip_hotswap = db.Column(db.Boolean)
    multi_ip = db.Column(db.Boolean)
    
    ###1.2.34
    is_allowed_access = db.Column(db.Boolean)
    ###1.2.45 1.2.46 MAC Addr
    route_mac = db.Column(db.String(24))
    switch_mac = db.Column(db.String(24))
    
    ###1.2.54 1.2.55 1.2.56 Nat IP
    nat_ip_enabled = db.Column(db.Boolean)
    nat_ipaddr = db.Column(db.String(32))
    nat_ipmask = db.Column(db.String(32))
    def __init__(self,id,lino,category_dict):
        self.id = id
        self.lino = lino
        self.stp_state = None
        #self.syn_timeout = None
        self.twin_active = None # using to global_forward_policy
        self.ipaddr = None
        self.ipmask = None
        self.twin_addr = None
        self.man_nic_addr = None
        self.virtual_ip_enabled = None
        self.vlan_trunk_enabled = None
        self.vlan_bind_channel = None
        self.post_fragment_enabled = None
        self.global_forward_policy = None
        self.line_work_enable = None
        self.default_vid = None
        #self.one_ip_hotswap = None
        self.multi_ip = None
        ## 1.2.34
        self.is_allowed_access = None
        ## 1.2.45 1.2.46 MAC
        self.route_mac = None
        self.switch_mac = None
        ### 1.2.54 1.2.55 1.2.56
        nat_ip_enabled = None
        nat_ipaddr = None
        nat_ipmask = None
        
        
        self.Modify(category_dict)


    def Modify(self, category_dict):
        category_keys = category_dict.keys()
        for category_key in category_keys:
            category_value = category_dict[category_key]
            if category_key == 'stp_state':
                self.stp_state = category_value
            #elif category_key == 'syn_timeout':
            #    self.syn_timeout = category_value
            elif category_key == 'twin_active':
                self.twin_active = category_value
            elif category_key == 'ipaddr':
                self.ipaddr = category_value
            elif category_key == 'ipmask':
                self.ipmask = category_value
            elif category_key == 'twin_addr':
                self.twin_addr = category_value
            elif category_key == 'man_nic_addr':
                self.man_nic_addr = category_value
            elif category_key == 'virtual_ip_enabled':
                self.virtual_ip_enabled = category_value
            elif category_key == 'vlan_trunk_enabled':
                self.vlan_trunk_enabled = category_value
            elif category_key == 'vlan_bind_channel':
                self.vlan_bind_channel = category_value
            elif category_key == 'post_fragment_enabled':
                self.post_fragment_enabled = category_value
            elif category_key == 'global_forward_policy':
                self.global_forward_policy = category_value
            elif category_key == 'line_work_enable':
                self.line_work_enable = category_value
            elif category_key == 'default_vid':
                self.default_vid = category_value
            # elif category_key == 'one_ip_hotswap':
            #     self.one_ip_hotswap = category_value
            elif category_key == 'multi_ip':
                self.multi_ip = category_value       
            ## 1.2.34
            elif category_key == 'is_allowed_access':
                self.is_allowed_access = category_value
            ## 1.2.45
            elif category_key == 'route_mac':
                self.route_mac = category_value
            elif category_key == 'switch_mac':
                self.switch_mac = category_value 

            ## 1.2.54 1.2.55 1.2.56
            elif category_key == 'nat_ip_enabled':
                self.nat_ip_enabled = category_value
            elif category_key == 'nat_ipaddr':
                self.nat_ipaddr = category_value
            elif category_key == 'nat_ipmask':
                self.nat_ipmask = category_value              
### route table
class DRouteTable(db.Model):
    __tablename__  = "route_table"
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    lino = db.Column(db.SmallInteger)
    routenumber = db.Column(db.Integer)
    ipaddr = db.Column(db.String(16))
    netmask = db.Column(db.String(16))
    gateway = db.Column(db.String(16))
    type = db.Column(db.String(16))
    def __init__(self,id,lino,routenumber, ipaddr, netmask, gateway,type):
        self.id = id
        self.lino = lino
        self.routenumber = routenumber
        self.ipaddr = ipaddr
        self.netmask = netmask
        self.gateway = gateway
        self.type = type
### channel infomation 
class DPrivateChannelInfo(db.Model):
    __tablename__ = "private_channel_info"
    keyid = db.Column(db.Integer,primary_key=True)
    id = db.Column(db.Integer)
    lino = db.Column(db.Integer)
    channelnumber = db.Column(db.Integer)
    channelnumber_band = db.Column(db.Integer)
    channelname = db.Column(db.String(32))
    teamid = db.Column(db.Integer)
    peer_addr = db.Column(db.String(16))
    work_model = db.Column(db.String(16))
    neg_status = db.Column(db.String(16))
    policy_num = db.Column(db.Integer)
    peer_prior = db.Column(db.String(8))
    peer_state = db.Column(db.String(16))
    last_neg_successtime = db.Column(db.String(32))
    neg_packets_sent = db.Column(db.Integer)
    neg_packets_recv = db.Column(db.Integer)
    neg_packets_err = db.Column(db.Integer)
    vlan_id = db.Column(db.Integer)


    def __init__(self,id, peer_addr, channelnumber, channelnumber_band, work_model, vlan_id,  channelname, teamid,lino, neg_status = "未知", policy_num = None, peer_prior = "未知", peer_state = "未知",last_neg_successtime = "未知",neg_packets_sent=None, neg_packets_recv=None, neg_packets_err =None):
        self.id = id
        self.channelname =  channelname
        self.peer_addr = peer_addr
        self.channelnumber = channelnumber
        self.channelnumber_band = channelnumber_band
        self.work_model = work_model
        self.vlan_id = vlan_id
        self.neg_status = neg_status
        self.policy_num = policy_num
        self.peer_prior = peer_prior
        self.peer_state = peer_state
        self.last_neg_successtime = last_neg_successtime
        self.neg_packets_sent = neg_packets_sent
        self.neg_packets_recv = neg_packets_recv
        self.neg_packets_err = neg_packets_err
        self.teamid = teamid
        self.lino = lino
### channel strategy
class DPrivateSecurityStrategy(db.Model):
    __tablename__ = 'private_security_strategy'
    keyid = db.Column(db.Integer,primary_key=True)

    id = db.Column(db.Integer)
    channelnumber = db.Column(db.Integer)
    strategynumber = db.Column(db.Integer)

    Source_Begin_IP = db.Column(db.String(32))
    Source_End_IP = db.Column(db.String(32))
    Dest_Begin_IP = db.Column(db.String(32))
    Dest_End_IP = db.Column(db.String(32))

    Port_Source_Begin = db.Column(db.Integer)
    Port_Source_End = db.Column(db.Integer)
    Port_Dest_Begin = db.Column(db.Integer)
    Port_Dest_End = db.Column(db.Integer)
    
    Direction = db.Column(db.SmallInteger)
    Protocol = db.Column(db.SmallInteger)
    WorkMode = db.Column(db.SmallInteger)
    NatMode = db.Column(db.Boolean)
    Policy_Name = db.Column(db.String(64))
    Policy_limit = db.Column(db.SmallInteger)
    Policy_level = db.Column(db.SmallInteger)

    def __init__(self, id, channelnumber,strategynumber, Source_Begin_IP="未知",Source_End_IP="未知", Dest_Begin_IP="未知",Dest_End_IP="未知",Port_Source_Begin=0,Port_Source_End=0,Port_Dest_Begin=0,Port_Dest_End=0, Direction=0, Protocol=0,WorkMode=0, NatMode=0, Policy_Name="未知", Policy_limit=0, Policy_level=0):
        
        self.id = id
        self.channelnumber = channelnumber
        self.strategynumber = strategynumber

        self.Source_Begin_IP = Source_Begin_IP
        self.Source_End_IP = Source_End_IP
        self.Dest_Begin_IP = Dest_Begin_IP
        self.Dest_End_IP = Dest_End_IP

        self.Port_Source_Begin = Port_Source_Begin
        self.Port_Source_End = Port_Source_End
        self.Port_Dest_Begin = Port_Dest_Begin
        self.Port_Dest_End = Port_Dest_End
        
        self.Direction = Direction
        self.Protocol = Protocol
        self.WorkMode = WorkMode
        self.NatMode = NatMode
        self.Policy_Name = Policy_Name
        self.Policy_limit = Policy_limit
        self.Policy_level = Policy_level


### vlan
class DVlanList(db.Model):
    __tablename__ = 'private_vlan_list'
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    lino = db.Column(db.SmallInteger)

    vid = db.Column(db.Integer)
    subnet = db.Column(db.String(16))
    netmask = db.Column(db.String(16))
    forward_next_hop = db.Column(db.String(16))
    backward_next_hop = db.Column(db.String(16))
    dev_in_this_vlan = db.Column(db.Boolean)
    is_apply_arp = db.Column(db.Boolean)

    def __init__(self, id, lino, vid, subnet, netmask, forward_next_hop, backward_next_hop, dev_in_this_vlan, is_apply_arp):
        self.id = id
        self.lino = lino
        self.vid = vid
        self.subnet = subnet
        self.netmask = netmask
        self.forward_next_hop = forward_next_hop
        self.backward_next_hop = backward_next_hop
        self.dev_in_this_vlan = dev_in_this_vlan
        self.is_apply_arp = is_apply_arp
   
  
class DPrivateCertInfo(db.Model):
    __tablename__ = "private_cert_info"
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    '''cert_id = db.Column(db.Integer)
    cert_name = db.Column(db.String(32))
    cert_type = db.Column(db.SmallInteger)
    cert_format = db.Column(db.SmallInteger)
    cert_length = db.Column(db.Integer)
    cert_content = db.Column(db.String(2000))'''
    cert_name = db.Column(db.String(32))
    province = db.Column(db.String(32))
    city = db.Column(db.String(32))
    organ = db.Column(db.String(64))
    depart = db.Column(db.String(32))
    name = db.Column(db.String(32))
    email = db.Column(db.String(64))
    cert_type = db.Column(db.SmallInteger)
    def __init__(self, id, cert_name,cert_type, province="未知", city="未知",organ="未知",depart="未知",name="未知",email="未知"):
        self.id = id
        self.cert_name = cert_name
        self.province = province
        self.city = city
        self.organ = organ
        self.depart = depart
        self.name = name
        self.email = email
        self.cert_type = cert_type
### log server
class DLogServerInfo(db.Model):
    __tablename__ = 'log_server_info'
    keyid = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.Integer)
    serverid = db.Column(db.Integer)
    ipaddr = db.Column(db.String(16))
    ports = db.Column(db.Integer)
    direction = db.Column(db.String(16))
    lino = db.Column(db.SmallInteger)
    vlan_id = db.Column(db.Integer)
    
    def __init__(self,id,serverid,ipaddr,ports,direction,lino,vlan_id):
        self.id = id
        self.serverid = serverid
        self.ipaddr = ipaddr
        self.ports = ports
        self.direction = direction
        self.lino = lino
        self.vlan_id = vlan_id


###初始化部分表
class LMIPAddr(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    IP1 = db.Column(db.String(128))
    IP2 = db.Column(db.String(128))
    IP3 = db.Column(db.String(128))
    IP4 = db.Column(db.String(128))

    def __init__(self, IP1, IP2, IP3, IP4):
        self.IP1 = IP1
        self.IP2 = IP2       
        self.IP3 = IP3
        self.IP4 = IP4

class LMRoute(db.Model):
    __tablename__ = "lead_machine_route"
    id = db.Column(db.Integer, primary_key=True)
    IPAddr = db.Column(db.String(16))
    Mask = db.Column(db.String(16))
    Gateway = db.Column(db.String(16))
    style = db.Column(db.String(16))
    interface = db.Column(db.String(16))

    def __init__(self, IPAddr, Mask, Gateway,style,interface):
        self.IPAddr = IPAddr
        self.Mask = Mask
        self.Gateway = Gateway
        self.style = style    
        self.interface = interface          

class LeadMachine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lmip = db.Column(db.String(128))
    outtime = db.Column(db.Integer)
    resendtime = db.Column(db.Integer)

    def __init__(self, lmip, outtime, resendtime):
        self.lmip = lmip
        self.outtime = outtime
        self.resendtime = resendtime

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    addlmflag = db.Column(db.Integer)
    createkeyflag = db.Column(db.Integer)
    exportlmcertflag = db.Column(db.Integer)
    restartflag = db.Column(db.Integer)
    configIPflag = db.Column(db.Integer)
    configrouteflag = db.Column(db.Integer)
    importCAflag = db.Column(db.Integer)
    importsyscertflag = db.Column(db.Integer)
    initialUSBKeyflag = db.Column(db.Integer)
    importUSBKeyflag = db.Column(db.Integer)

    def __init__(self, addlmflag=0, createkeyflag=0, exportlmcertflag=0, configIPflag=0, restartflag=0, configrouteflag=0,importCAflag=0,importsyscertflag=0,initialUSBKeyflag=0,importUSBKeyflag=0):
        self.addlmflag = addlmflag
        self.createkeyflag = createkeyflag
        self.exportlmcertflag = exportlmcertflag
        self.configIPflag = configIPflag
        self.restartflag = restartflag
        self.configrouteflag = configrouteflag
        self.importCAflag = importCAflag
        self.importsyscertflag = importsyscertflag
        self.initialUSBKeyflag = initialUSBKeyflag
        self.importUSBKeyflag = importUSBKeyflag

class DLeadMachineCert(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    certname = db.Column(db.String(64))
    certpath = db.Column(db.String(128))

    def __init__(self,certname, certpath):
        self.certname = certname
        self.certpath = certpath
def getPlatform(url):
    if "taobao.com" in url:
        return "淘宝"
    if "tmall.com" in url:
        return "天猫"
    if "pinduoduo.com" in url or  "yangkeduo.com" in url:
        return "拼多多"
    return "未知"
def get_id(src):
    if "http" in src or "https" in src:
        parse = urlparse.urlparse(src)
        if "detail.1688.com" in parse.netloc:
            try:
                return parse.path.split(".")[0].split("/")[-1]
            except:
                return src
        else:
            query = urlparse.parse_qs(parse.query)
            if query.has_key("id"):
                return query["id"][0]
            elif query.has_key("item_id"):
                return query["item_id"][0]
            elif query.has_key("goods_id"):
                return query['goods_id']
    return src
def format_float(f):
    return "%0.2f" % (f * 100) +  '%'
class Good(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    goodId = db.Column(db.String(32))
    goodTitle = db.Column(db.String(128))
    goodDescription = db.Column(db.String(128))
    goodUrl = db.Column(db.String(128))
    goodSrcUrl = db.Column(db.String(128))
    goodImgUrl = db.Column(db.String(64))
    goodCost = db.Column(db.Float)
    goodPrice = db.Column(db.Float)
    goodExpress = db.Column(db.String(128))
    goodPostage = db.Column(db.Float)
    goodExtra = db.Column(db.String(256))
    def __init__(self):
        self.goodId = "6147245"
        self.goodTitle = "吸尘器"
        self.goodDescription = "小型"
        self.goodUrl = "https://detail.tmall.com/item.htm?id=612947314674"
        self.goodSrcUrl = "http://mobile.yangkeduo.com/goods.html?goods_id=2823236263"
        self.goodImgUrl = "/static/img/green.png"
        self.goodCost = 6.6
        self.goodPrice = 18.8
        self.goodExpress = "韵达 顺丰"
        self.goodPostage = 10
        self.goodExtra = ""
class GoodBaseInfo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    good_id = db.Column(db.String(32))
    good_title = db.Column(db.String(64))
    good_description = db.Column(db.String(128))
    good_image_url = db.Column(db.String(128))
    good_has_video = db.Column(db.Boolean)
    coupon = db.Column(db.Float) ## 优惠券
    create_time = db.Column(db.Float)
    good_prize = db.Column(db.Float) ## 赠品
    category = db.Column(db.String(64)) ## 类目

    def __init__(self, _good_id = "", _category = "", _good_title = "", _good_description = "", _good_image_url =  "", _good_has_video = False, _coupon = 0, _good_prize = 0):
        self.good_id = _good_id
        self.good_title = _good_title
        self.good_description = _good_description
        self.good_image_url = _good_image_url
        self.good_has_video = _good_has_video
        self.create_time = time.time()
        self.coupon = _coupon
        self.good_prize = _good_prize
        self.category = _category

class GoodSkuInfo(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    good_id = db.Column(db.String(32))
    sku_id = db.Column(db.String(64))
    sku_url = db.Column(db.String(128)) ## 店铺链接
    sku_price = db.Column(db.Float)
    create_time = db.Column(db.Float)
    def __init__(self, _good_id = "", _sku_id = "", _sku_url =  "",  _good_price  = 0):
        self.good_id = _good_id
        self.sku_url = _sku_url
        self.sku_id = _sku_id
        self.sku_price = _good_price
        self.create_time = time.time()
        self.sku_price_90 = _good_price * 0.9
        self.sku_price_80 = _good_price * 0.8
    def reset(self):
        self.sku_url=""
        self.sku_price = 0
        self.create_time = time.time()
        self.sku_price_90 = 0
        self.sku_price_80 = 0


MALL_REBATE = 0.05 ## 天猫扣点
class Profit:
    def __init__(self):
        ##正常的利润
        self.profit = ""
        self.profit_rate = ""
        ## 30%佣金 服务费0 加劵
        self.profit_1 = ""
        self.profit_1_rate = ""
        ## 20%佣金 服务费0 加劵
        self.profit_2 = ""
        self.profit_2_rate = ""
        ## 30%佣金 服务费0 不加劵
        self.profit_3 = ""
        self.profit_3_rate = ""
        ## 20%佣金 服务费0 不加劵
        self.profit_4 = ""
        self.profit_4_rate = ""
        ## 20%佣金 服务费5% 加劵
        self.profit_5 = ""
        self.profit_5_rate = ""
        ## 20%佣金 服务费5% 不加劵
        self.profit_6 = ""
        self.profit_6_rate = ""

class SkuProxyInfo(db.Model):
    proxy_id = db.Column(db.Integer, primary_key = True)
    good_id = db.Column(db.String(32))
    sku_id = db.Column(db.String(64))
    good_proxy_url = db.Column(db.String(128)) ## 代发链接
    good_proxy_platform = db.Column(db.String(32)) ## 代发平台
    good_proxy_id = db.Column(db.String(32)) ## 代发ID
    good_express = db.Column(db.String(128)) ## 快递
    good_postage = db.Column(db.Float) ## 快递费
    postage_address = db.Column(db.String(32)) ## 发货地址
    produce_address = db.Column(db.String(32)) ##  产地
    good_cost = db.Column(db.Float) ## 成本价
    good_extra = db.Column(db.String(256)) ## 备注
    create_time = db.Column(db.Float)
    qualification = db.Column(db.String(32)) ## 资质
    day_limit = db.Column(db.Float) ## 日常限价
    activity_limit = db.Column(db.Float) ## 活动限价
    def __init__(self, _good_id, _sku_id, _good_proxy_url = "", _good_express = "", _good_postage = 0, _postage_address = "", _produce_address = "", _good_cost = 0, _qualification="", _day_limit = 0, _activity_limit = 0, _good_extra = ""):
        self.good_id = _good_id
        self.sku_id = _sku_id
        self.good_proxy_url = _good_proxy_url
        self.good_proxy_platform = getPlatform(_good_proxy_url)
        self.good_proxy_id = get_id(_good_proxy_url)
        self.good_express = _good_express
        self.good_cost = _good_cost
        self.postage_address = _postage_address
        self.produce_address = _produce_address
        self.good_postage = _good_postage
        self.good_extra = _good_extra
        self.day_limit = _day_limit
        self.activity_limit = _activity_limit
        self.sku_info = GoodSkuInfo()
        self.good_base_info = GoodBaseInfo()
        self.profit = Profit()
        self.create_time = time.time()
    def reset(self):
        self.good_proxy_url = ""
        self.good_proxy_platform = ""
        self.good_proxy_id = ""
        self.good_express = ""
        self.good_cost = 0
        self.postage_address = ""
        self.produce_address = ""
        self.good_postage = ""
        self.good_extra = ""
        self.day_limit = 0
        self.activity_limit = 0
        self.sku_info = GoodSkuInfo()
        self.good_base_info = GoodBaseInfo()
        self.profit = Profit()
        self.create_time = time.time()
    def set_parent_info(self, _good_base_info, _sku_info):
        if _good_base_info is not None:
            self.good_base_info = _good_base_info
        if _sku_info is not None:
            self.sku_info = _sku_info
        self.calculate_price()
    def calculate_price(self):
        self.profit = Profit()
        if self.sku_info.sku_price <= 0:
            return
        ## 真实成本 = 基础成本 + 赠品价值 + 代发邮费
        real_cost = self.good_cost + self.good_base_info.good_prize + self.good_postage
        ## 用劵销售价格
        real_price = self.sku_info.sku_price - self.good_base_info.coupon
        ## 不用劵销售价格
        real_price_no = self.sku_info.sku_price
        if real_price <= 0:
            return
        ##正常的利润
        self.profit.profit = self.sku_info.sku_price * (1 - MALL_REBATE) - real_cost
        self.profit.profit_rate = format_float(self.profit.profit / real_price)
        ## 30%佣金 服务费0 加劵
        self.profit.profit_1 = (real_price - real_price * (0.3 + MALL_REBATE) - real_cost)
        self.profit.profit_rate_1 = format_float(self.profit.profit_1 / real_price)
        ## 20%佣金 服务费0 加劵
        self.profit.profit_2 = (real_price - real_price * (0.2 + MALL_REBATE) - real_cost)
        self.profit.profit_rate_2 = format_float(self.profit.profit_2 / real_price)
        ## 30%佣金 服务费0 不加劵
        self.profit.profit_3 = (real_price_no - real_price_no * (0.3 + MALL_REBATE) - real_cost)
        self.profit.profit_rate_3 = format_float(self.profit.profit_3 / real_price_no)
        ## 20%佣金 服务费0 不加劵
        self.profit.profit_4 = (real_price_no - real_price_no * (0.2 + MALL_REBATE) - real_cost)
        self.profit.profit_rate_4 = format_float(self.profit.profit_4 / real_price_no)
        ## 20%佣金 服务费5% 加劵
        self.profit.profit_5 = (real_price - real_price * (0.2 + 0.05 + MALL_REBATE) - real_cost)
        self.profit.profit_rate_5 = format_float(self.profit.profit_5 / real_price)
        ## 20%佣金 服务费5% 不加劵
        self.profit.profit_6 = (real_price_no - real_price_no * (0.2 + 0.05 + MALL_REBATE) - real_cost)
        self.profit.profit_rate_6 = format_float(self.profit.profit_6 / real_price_no)

