#!/usr/bin/env python
# coding=utf-8
from flask.ext.sqlalchemy import SQLAlchemy

from CTFd.models import LeadMachine, Cipermachine
from CTFd import models, ukey
from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from struct import *
from time import ctime,sleep,time
from os import system
from flask import current_app as app, request, session
import socket
import struct
import ctypes
import datetime

import thread, time
import MySQLdb

lock = thread.allocate_lock()  
lock1 = thread.allocate_lock()
lock_sendpacket = thread.allocate_lock()  

PacketStack = { }
SendPacketStack = {}
Thread = None
Thread1 = None
Thread2 = None
Thread3 = None
TimeStamp = datetime.datetime.now()


UkeyFlag = True
Uid = ''
authority = app.config['MYSQL_USER']
password = app.config['MYSQL_PASSWORD']
name = app.config['DATEBASE_NAME']
FrontendprocessorIP = '11.0.0.3'

def UkeyContect(sql):
    db = MySQLdb.connect("localhost",authority,password,name,charset='utf8' ) 
    cursor = db.cursor()
    cursor.execute(sql)
    results = cursor.fetchall()
    db.close()
    return results

def SocketReceive():
    global lock, PacketStack,TimeStamp
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 254)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    try:
        while  True:
            BufferSize = 65536
            packet_receives = s.recvfrom(BufferSize)
            now = datetime.datetime.now()
            packet_receive = packet_receives[0]
            ip_header = packet_receive[0:20]

            ip_protocol = unpack('!B',ip_header[9])[0]

            if ip_protocol != 254:
                continue
            snh=packet_receive[20:24]
            sn = unpack('!L', snh)[0]

            lock.acquire() 
            newpacket = {sn : [packet_receive, now]} 
            PacketStack.update(newpacket) 
            lock.release() 
    except Exception,e:
        try:
            lock.release()
        except Exception:
            pass
        print e
        s.close()
        Thread = None
        return
        
def ClearPacket():
    timegap = 10
    global lock, PacketStack ,Uid , UkeyFlag
    try:
        while True:
            time.sleep(10)
            now = datetime.datetime.now()

            lock.acquire()



            for key in PacketStack.keys():
                delta = now - PacketStack[key][1] 
                if delta.total_seconds() > timegap:
                    print now
                    print PacketStack[key][1]
                    PacketStack.pop(key)
            lock.release()
            status = ukey.m_ukey_cycle_check(Uid)
            
            if status != 0:
                UkeyFlag = False
            else:
                UkeyFlag = True
            TimeStamp = now     
    except Exception,e:
        try:
            lock.release()
        except:
            pass
        print e
        Thread1 = None

def CheckUkey():
    global UkeyFlag
    # now = datetime.datetime.now()
    # delta = now - TimeStamp
    # if delte.total_seconds() > 10:
    #     return False
    # else:
    ##return True
    return UkeyFlag

def SetUid(a):
    global Uid
    Uid = a
def GetUid():
    global Uid
    return Uid
def SetFlag(b):
    global UkeyFlag
    UkeyFlag = b

def SocketTransport(packet_send, dest_host, sn = 0,Timeout = 3):
    
    global PacketStack, lock, Thread, Thread1
    #global SendPacketStack ## cache of packet

    leadmachine = LeadMachine.query.first()
    FrontendprocessorIP = leadmachine.lmip
    Timeout = max(Timeout,leadmachine.outtime)
    ##print Timeout
    SendTimes = leadmachine.resendtime + 1
    
    if Thread == None:
       
        Thread = thread.start_new_thread(SocketReceive, ())
        print 'Receive thread is starting!'
        
    if Thread1 == None:
        Thread1 = thread.start_new_thread(ClearPacket,())
        print 'Clear thread is stating!'

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 254)
    
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    try:
        status = s.sendto(packet_send, (FrontendprocessorIP, 80))
    except Exception, e:
        print e
        print "Error!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    
    ResultForReturn = None
    while(SendTimes > 1):
        # print 'SendTimes =  ', SendTimes
        # print 'Timeout = ',Timeout
        Timeout = max(Timeout,leadmachine.outtime)
        while Timeout > 0:

            lock.acquire() 
            
            if sn + 1 in PacketStack.keys():
                packet_receive = PacketStack.pop(sn + 1)[0] 
                lock.release()  
                ResultForReturn = packet_receive
                break
            else:
                Timeout = Timeout - 0.2
                lock.release()  
               
            time.sleep(0.2)
        if(ResultForReturn == None):
            try:
                status = s.sendto(packet_send, (FrontendprocessorIP, 80))
            except Exception, e:
                print e
                print "Error!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"            
            SendTimes = SendTimes - 1
        else:
            break
    return ResultForReturn

def Contect(sql):
    db = MySQLdb.connect("localhost",authority,password,name,charset='utf8' ) 
    cursor = db.cursor()
    cursor.execute(sql)
    results = cursor.fetchall()
    db.close()
    return results

def SpingSaveData(sql):
    db = MySQLdb.connect("localhost",authority,password,name,charset='utf8' )
    cursor = db.cursor()
    cursor.execute(sql)
    cursor.close()
    db.commit()
    db.close()

def SpingReceive():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    
    try:
        while  True:
            BufferSize = 65536
            packet_receives = s.recvfrom(BufferSize)
            now = datetime.datetime.now()
            packet_receive = packet_receives[0]
           
            ip_header = packet_receive[0:20]
            ip_protocol = unpack('!B',ip_header[9])[0]
            if ip_protocol != 253:
                continue
            snh = packet_receive[20:24]
            header = unpack('!BBH', snh)
            rtype = header[0]
            state = header[1]
            sn = header[2]
            sping_receive_pack = packet_receive[24:40]
            sping_receive = unpack('16s', sping_receive_pack)
            sping_IP = sping_receive[0].strip('\x00')
            lock1.acquire()
            
            result = Contect("SELECT * FROM cipermachine where ip='%s'"%sping_IP)
            result = list(result[0])
            if len(result) > 0:
                if result[-3] == False:
                    result[-3] = 1
                    result[-2] = int(time.time())
                    sql1 = "update cipermachine set isonline='%s',spingtime='%s' where ip='%s'" % (result[-3],result[-2],sping_IP)
                    SpingSaveData(sql1)

            lock1.release()  

    except Exception,e:
        try:
            lock.release()
        except Exception:
            pass
        print e
        s.close()
        Thread2 = None
        return

def SpingTransport():
    global Thread2
    if Thread2 == None:
        Thread2 = thread.start_new_thread(SpingReceive, ())
        print 'Sping Receive thread is starting!'


def CheckTime():
    while True:
        lock1.acquire()
        recodes = Contect("SELECT * FROM cipermachine")
        for i in range(len(recodes)):
            recode = list(recodes[i])
            if recode[-3] == 1:
                now = int(time.time())
                compare = now - int(recode[-2])
                if compare > 180:
                    recode[-3] = 0
                    sql2 = "update cipermachine set isonline='%s'" % recode[-3]
                    SpingSaveData(sql2)
        lock1.release()  
        time.sleep(5 * 60 * 1000)


def CheckSping():
    global Thread3

    if Thread3 == None:
        Thread3 = thread.start_new_thread(CheckTime, ())
        print 'Sping Check is starting!'
    