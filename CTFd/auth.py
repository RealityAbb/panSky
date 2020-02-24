# coding=utf-8
from flask import render_template, request, redirect, abort, jsonify, url_for, session, flash, send_from_directory
from CTFd.utils import sha512, authed, judge_result, check_ip, check_mac, allowed_file, AddCommonStatus, AddPrivateStatus
from CTFd import initial, ukey, Transport
from CTFd.models import db, Users, SysIPAddress, SystemRoutes, LeadMachine, Cipermachine, Terminallogs, LeadMachinelogs, EquipmentsStatus, Certificates, CertDetail, ChannelStatus, ChannelNumber,DSecurityStrategy,Tree,DRouteTable,DPrivateCertInfo,LMRoute,DPrivateChannelInfo,DStandarCertificate,UploadCertificates
from CTFd import operationequipment, models,privatesystem,privatechannel, privatestrategy,privatenetwork,privatevlan,privatelog,privatesecurity,privatesundry,privatecert
from itsdangerous import TimedSerializer, BadTimeSignature
from passlib.hash import bcrypt_sha256
from flask import current_app as app
from werkzeug.utils import secure_filename
from CTFd.Transport import lock1

from struct import *
from generalfunction import SwitchErrorCode
import base64
import logging
import time
import datetime
import socket
import hashlib
import re
import os
import sys
import socket
import struct
import ctypes
import zipcompress
import MySQLdb
authority = app.config['MYSQL_USER']
password = app.config['MYSQL_PASSWORD']
name = app.config['DATEBASE_NAME']
reload(sys)
sys.setdefaultencoding('utf-8')
def init_auth(app):
    @app.context_processor
    def inject_user():
        if authed():
            return dict(session)
        return dict()

    def DeleteData(sql):
        db = MySQLdb.connect("localhost",authority,password,name,charset='utf8' )
        cursor = db.cursor()
        cursor.execute(sql)
        cursor.close()
        db.commit()
        db.close()

    @app.route('/login',methods=['POST','GET'])
    def login():
        if authed():
            return redirect('/base')
        if request.method == 'POST':
            errors = []
            status = ukey.m_ukey_prepare()
            if status != 0:
                errors = judge_result(status)
                return render_template('login.html',errors=errors)
            else:
                status2 = ukey.m_ukey_get_info()
                result = status2['r']
                ukeyid = status2['id_ptr'].split("\x00")[0]
                if result != 0:
                    errors = judge_result(result)
                    return render_template('login.html',errors=errors)
                else:
                    user = Users.query.filter_by(ukeyid=ukeyid).first()
                    if user == None:
                        errors.append("没有这个用户！")
                        return render_template('login.html',errors=errors)
                    else:
                        if user.losesign == 0:
                            errors.append("此用户已申请挂失，无法使用！")
                            return render_template('login.html',errors=errors)
                        else:
                            epassword = request.form['epassword']
                            password = base64.decodestring(epassword)
                            filename = user.pk
                            if filename != "":
                                filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                                certfile = open(filepath, 'r')
                                data = certfile.read() 
                                parameters = [len(data), data]
                                importcert = initial.CGetCertPK(parameters)
                                status3,pk = importcert.SendAndReceive()
                                if status3 != 0:
                                    errors = judge_result(status3)
                                    return render_template('login.html',errors=errors)
                                else:
                                    status4 = ukey.m_ukey_authenticate(user.name,password,user.ukeyid,pk,64)
                                    if status4 != 0:
                                        errors = judge_result(status4)
                                        return render_template('login.html',errors=errors)
                                    else:
                                        flag = True
                                        Transport.SetFlag(flag)
                                        Transport.SetUid(user.ukeyid)
                                        session.paramanent = False
                                        session['username'] = user.name
                                        session['uid'] = user.ukeyid
                                        session['admin'] = user.admin
                                        session['nonce'] = sha512(os.urandom(10))
                                        db.session.close()
                                        rank = "通告"
                                        now = int(time.time())
                                        name = user.name
                                        style = "LOG_INFO"
                                        content = "用户登录"
                                        log = Terminallogs(rank,now,name,style,content)
                                        db.session.add(log)
                                        db.session.commit()
                                        # if user.admin == 2:
                                        #     Transport.SpingTransport()
                                        #     Transport.CheckSping()
                                        db.session.close()
                                        return redirect('/base')
                            else:
                                errors.append("此用户没有公钥证书！")
                                return render_template('login.html',errors=errors)                             
        else:
            db.session.close()
            return render_template('login.html')
    @app.route('/relogin', methods=['POST','GET'])
    def relogin():
        errors = []
        errors.append("Ukey验证失败，请重新登录!")
        return render_template('login.html',errors=errors)        

    # @app.route('/login',methods=['POST','GET'])
    # def login():
    #     if authed():
    #         return redirect('/base')
    #     if request.method == 'POST':
    #         errors = []
    #         status = ukey.m_ukey_prepare()
    #         if status != 0:
    #             errors = judge_result(status)
    #             return render_template('login.html',errors=errors)
    #         else:
    #             status2 = ukey.m_ukey_get_info()
    #             result = status2['r']
    #             ukeyid = status2['id_ptr'].split("\x00")[0]
    #             if result != 0:
    #                 errors = judge_result(result)
    #                 return render_template('login.html',errors=errors)
    #             else:
    #                 user = Users.query.filter_by(ukeyid=ukeyid).first()
    #                 if user == None:
    #                     errors.append("没有这个用户！")
    #                     return render_template('login.html',errors=errors)
    #                 else:
    #                     if user.losesign == 0:
    #                         errors.append("此用户已申请挂失，无法使用！")
    #                         return render_template('login.html',errors=errors)
    #                     else:
    #                         epassword = request.form['epassword']
    #                         password = base64.decodestring(epassword)
    #                         filename = user.pk
    #                         if filename != "":
    #                             filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
    #                             certfile = open(filepath, 'r')
    #                             data = certfile.read() 
    #                             parameters = [len(data), data]
    #                             importcert = initial.CGetCertPK(parameters)
    #                             status3,pk = importcert.SendAndReceive()
    #                         #     if status3 != 0:
    #                         #         errors = judge_result(status3)
    #                         #         return render_template('login.html',errors=errors)
    #                         #     else:
    #                         #         status4 = ukey.m_ukey_authenticate(user.name,password,user.ukeyid,pk,64)
    #                         #         if status4 != 0:
    #                         #             errors = judge_result(status4)
    #                         #             return render_template('login.html',errors=errors)
    #                         #         else:
    #                         #             session.paramanent = False
    #                         #             session['username'] = user.name
    #                         #             session['uid'] = user.ukeyid
    #                         #             session['admin'] = user.admin
    #                         #             session['nonce'] = sha512(os.urandom(10))
    #                         #             db.session.close()
    #                         #             flag = True
    #                         #             Transport.SetUid(flag)
    #                         #             rank = "通告"
    #                         #             now = int(time.time())
    #                         #             name = user.name
    #                         #             style = "LOG_INFO"
    #                         #             content = "用户登录"
    #                         #             log = Terminallogs(rank,now,name,style,content)
    #                         #             db.session.add(log)
    #                         #             db.session.commit()
    #                         #             # if user.admin == 2:
    #                         #             #     Transport.SpingTransport()
    #                         #             #     Transport.CheckSping()
    #                         #             db.session.close()
    #                         #             return redirect('/base')
    #                         # else:
    #                         #     errors.append("此用户没有公钥证书！")
    #                         #     return render_template('login.html',errors=errors) 
    #                             session.paramanent = False
    #                             session['username'] = user.name
    #                             session['uid'] = user.ukeyid
    #                             session['admin'] = user.admin
    #                             session['nonce'] = sha512(os.urandom(10))
    #                             rank = "普通"
    #                             now = int(time.time())
    #                             name = user.name
    #                             style = "LOG_INFO"
    #                             content = "用户登录"
    #                             log = Terminallogs(rank,now,name,style,content)
    #                             db.session.add(log)
    #                             db.session.commit()
    #                             # if user.admin == 2:
    #                             #     Transport.SpingTransport()
    #                             #     Transport.CheckSping()
    #                             db.session.close()
    #                             return redirect('/base')
    #                         else:
    #                             errors.append("此用户没有公钥证书！")
    #                             return render_template('login.html',errors=errors)                                
    #     else:
    #         db.session.close()
    #         return render_template('login.html')

    @app.route('/netset', methods=['GET'])
    def route():
        user1 = Users.query.filter_by(admin=1).first()
        if user1 != None and session.get('admin') == user1.admin:
            lmipaddress = ['','','','']
            lmipmask = ['','','','']        
            querypredeviceip = initial.QueryPredeviceIP()
            status,ip,ipmask = querypredeviceip.SendAndReceive()
            if status == 0:
                lmipaddress = ip
                lmipmask = ipmask
            db.session.close()
            return render_template('netset.html', lmipaddress = lmipaddress, lmipmask=lmipmask)
        else:
            return redirect('/')  

    @app.route('/netsetroute',methods=['GET'])
    def route2():
        user1 = Users.query.filter_by(admin=1).first()
        if user1 != None and session.get('admin') == user1.admin:
            querypredeviceroute = initial.QueryPredeviceRoute()
            status = querypredeviceroute.SendAndReceive()
            if status == 0:
                lmroute = LMRoute.query.all()
                count = len(lmroute)
                db.session.close()
                return render_template('netsetroute.html', lmroutes = lmroute, count= count)
            else:
                lmroute = LMRoute.query.all()
                count = len(lmroute)
                db.session.close()
                return render_template('netsetroute.html',lmroutes = lmroute,count = count)
        else:
            return redirect ( '/' )

    @app.route('/netset/deleteroute',methods=['POST'])
    def delete_route():
        route = int(request.form['style'])
        IP = (request.form['ip']).encode('utf-8')
        mask = (request.form['mask']).encode('utf-8')
        gateway = (request.form['gateway']).encode('utf-8')
        interface = int(request.form['interfacen'])
        legal1 = check_ip(IP)
        legal2 = check_ip(mask)
        legal3 = check_ip(gateway)
        if legal1 & legal2 & legal3 == 0:
            return "-3"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(IP))[0]
            mask1 = struct.unpack('!L',socket.inet_aton(mask))[0]
            ip = ip1 & mask1
            rip = socket.inet_ntoa(struct.pack('I',socket.htonl(ip)))
            operation = 2
            parameters = [operation,route, IP, mask, gateway,interface]
            configpredeviceroute = initial.ConfigPredeviceRoute(parameters)
            status = configpredeviceroute.SendAndReceive()
            print status
            if status == 0:
                querypredeviceroute = initial.QueryPredeviceRoute()
                rank = "重要"
                now = int(time.time())
                name = session['username']
                style = "LOG_WARNING"
                content = "删除路由"
                log = Terminallogs(rank,now,name,style,content)
                db.session.add(log)
                db.session.commit()
                db.session.close()
                return str(status)
            else:
                return str(status)

    @app.route('/nettime',methods=['GET'])
    def nettime():
        leadmachines = LeadMachine.query.first()
        outtime = leadmachines.outtime

        resend = leadmachines.resendtime
        return render_template('nettime.html', out_time = outtime , resend_time = resend)


    @app.route('/setouttime',methods=['POST'])
    def setouttime():
        outtime = request.form['outtime']
        leadmachines = LeadMachine.query.first()
        leadmachines.outtime = outtime
        db.session.add(leadmachines)
        db.session.commit()
        return "0"

    @app.route('/setresendtimes',methods=['POST'])
    def setresendtimes():
        resend = request.form['resend']
        leadmachines = LeadMachine.query.first()
        leadmachines.resendtime = resend
        db.session.add(leadmachines)
        db.session.commit()
        return "0"

    @app.route('/equipment',methods=['GET'])
    def user2():
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            page = request.args.get('page',1, type=int)
            pagination=Cipermachine.query.paginate(page,per_page=15,error_out=False)
            cipermachine = pagination.items
            total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
            viewfunc = ".user2"
            return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count)
        else:
            return redirect('/')

    def Contect(sql):
        db = MySQLdb.connect("localhost",authority,password,name,charset='utf8' )
        cursor = db.cursor()
        cursor.execute(sql)
        results = cursor.fetchall()
        db.close()
        return results

    @app.route('/tree',methods=['POST'])
    def get_tree():
        results = Contect("SELECT * FROM tree ")
        province = []
        
        for row in results:
            province.append(row[1])
            
        provinceSet =set(province)

        provinceAll=[]
        for emtprovinceSet in provinceSet:
            provincedict = {}
            
            city = []
            sql_province = "SELECT city FROM tree where province='%s'" % emtprovinceSet
            result_province = Contect(sql_province)
            for emtcity in result_province:
                city.append(emtcity[0])
            citySet = set(city)
            cityAll = []
            for emtcitSet in citySet:
                part = []
                citydict = {}
                sql_city = "SELECT part FROM tree where province='%s' and city='%s'" % (emtprovinceSet,emtcitSet)
                result_city = Contect(sql_city)
                for emtpart in result_city:
                    part.append(emtpart[0])
                partSet = set(part)
                partAll = []
                for emtpartSet in partSet:
                    partdict = {}

                    fourth = []
                    sql_fourth = "SELECT fourth FROM tree where province='%s' and city='%s' and part='%s'" % (emtprovinceSet,emtcitSet,emtpartSet)
                    result_fourth = Contect(sql_fourth)
                    for emtfourth in result_fourth:
                        fourthdict = {}
                        result_cipermachine = Contect("SELECT fourth FROM cipermachine where province='%s' and city='%s'and part='%s' and fourth='%s'" % (emtprovinceSet,emtcitSet,emtpartSet,emtfourth[0]))
                        if len(emtfourth[0])>0:
                            fourthdict['text'] = emtfourth[0] + "     (" + str(len(result_cipermachine)) + ")"
                            fourth.append(fourthdict)
                    result_cipermachine_3 = Contect("SELECT fourth FROM cipermachine where province='%s' and city='%s'and part='%s' " % (emtprovinceSet,emtcitSet,emtpartSet))
                    if len(emtpartSet)>0:
                        partdict["text"] = emtpartSet + "     (" + str(len(result_cipermachine_3)) + ")"
                        partdict["nodes"] = fourth
                        partAll.append(partdict)
                result_cipermachine_2 = Contect("SELECT fourth FROM cipermachine where province='%s' and city='%s'" % (emtprovinceSet,emtcitSet))
                if len(emtcitSet)>0:
                    citydict["text"]=emtcitSet + "     (" + str(len(result_cipermachine_2)) + ")"
                    citydict["nodes"] = partAll
                    cityAll.append(citydict)
            result_cipermachine_1 = Contect("SELECT fourth FROM cipermachine where province='%s'" % (emtprovinceSet))
            if len(emtprovinceSet)>0:
                provincedict["text"]=emtprovinceSet + "     (" + str(len(result_cipermachine_1)) + ")"
                provincedict["nodes"] = cityAll
                provinceAll.append(provincedict)
        #print provinceAll
        return jsonify(tree=provinceAll)   
        
        
    @app.route('/equipment/addtree',methods=['POST'])
    def add_tree():
        province = request.form['tprovince']
        city = request.form['tcity']
        part = request.form['tpart']
        fourth = request.form['tfourth']
        tree = Tree(province,city,part,fourth)
        record = Tree.query.filter_by(province=province,city=city,part=part,fourth=fourth).first()
        if record == None:
            db.session.add(tree)
            db.session.commit()
            rank = "重要"
            now = int(time.time())
            name = session['username']
            style = "LOG_WARNING"
            content = "添加节点"
            log = Terminallogs(rank,now,name,style,content)
            db.session.add(log)
            db.session.commit()
            db.session.close()
            return redirect('/equipment')
        else:
            return redirect('/equipment')

    @app.route('/equipment/deletetree',methods=['POST'])
    def delete_tree():
        province = request.form['firstnode'].encode('utf-8')
        city = request.form['secondenode'].encode('utf-8')
        part = request.form['thirdnode'].encode('utf-8')
        fourth = request.form['fourthnode'].encode('utf-8')
        if city == '' and part == '' and fourth == '':
            trees = Tree.query.filter_by(province=province).all()
            for tree in trees:
                db.session.delete(tree)
        elif part == '' and fourth == '':
            trees = Tree.query.filter_by(province=province,city=city).all()
            for tree in trees:
                tree.city = ""
                tree.part = ""
                tree.fourth = ""
                db.session.add(tree)
        elif fourth == '':
            trees = Tree.query.filter_by(province=province,city=city,part=part).all()
            for tree in trees:
                db.session.delete(tree)
                tree.part = ""
                tree.fourth = ""
                db.session.add(tree)
        else:
            trees = Tree.query.filter_by(province=province,city=city,part=part,fourth=fourth).all()
            for tree in trees:
                db.session.delete(tree)
                tree.fourth = ""
                db.session.add(tree)
        db.session.commit()
        db.session.close()
        rank = "重要"
        now = int(time.time())
        name = session['username']
        style = "LOG_WARNING"
        content = "删除路由"
        log = Terminallogs(rank,now,name,style,content)
        db.session.add(log)
        db.session.commit()
        db.session.close()
        return redirect('/equipment')


    @app.route('/machineshow', methods=['POST'])
    def show_machine():
        if request.method == 'POST':
            firstnode = request.form['firstnode']
            secondnode = request.form['secondnode']
            thirdnode = request.form['thirdnode']
            fourthnode = request.form['fourthnode']
            lock1.acquire()
            if secondnode == '' and thirdnode == '' and fourthnode == '':
                finalresult = Cipermachine.query.filter_by(province=firstnode).all()
            elif thirdnode == '' and fourthnode == '':
                finalresult = Cipermachine.query.filter_by(province=firstnode,city=secondnode).all()
            elif fourthnode == '':
                finalresult = Cipermachine.query.filter_by(province=firstnode,city=secondnode,part=thirdnode).all()
            else:
                finalresult = Cipermachine.query.filter_by(province=firstnode,city=secondnode,part=thirdnode,fourth=fourthnode).all()
            lock1.release()
            return render_template('equipmentbase.html',cipermachines=finalresult)
    
    @app.route('/equipment/new', methods=['POST'])
    def add_equipment():
        ip = request.form['ip']
        record = Cipermachine.query.filter_by(ip=ip).first()
        if record == None:
            files = request.files.getlist('files[]')               
            for f in files:
                if f and allowed_file(f.filename):
                    filen = secure_filename(f.filename)
                    filename = ip + '.der'
                    if len(filen) <= 0:
                        continue
                    cert_type_code = 5            
                    cerstyle = int(request.form['cerstyle'])
                    if cerstyle == 1:
                        filename = "ecc_" + filename
                    readonly = 0

                    if(cerstyle == 1):
                        deletefilename = ip
                    else:
                        deletefilename = "ecc_" + ip
                    deletecert = initial.CDeleteCert([deletefilename])
                    status = deletecert.SendAndReceive()
                    ##print "1111111111111111111"
                    if(status == -2):
                        ##print "22222222222222222222222"
                        AlertInfo = SwitchErrorCode(status)
                        db.session.close()
                        page = request.args.get('page',1, type=int)
                        pagination=Cipermachine.query.paginate(page,per_page=15,error_out=False)
                        cipermachine = pagination.items
                        total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
                        viewfunc = ".user2"
                        return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo=AlertInfo)
                    ##print "3333333333333333333"
                    cert_format = int(request.form['cert_format']) 
                    cert_type = (cerstyle *16) + (readonly * 8) + cert_type_code
                    filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                    f.save(filepath)
                    certfile = open(filepath, 'r')
                    data = certfile.read()
                    certfile.close()
                    Peer_ip = (request.form['ip']).encode('utf-8')
                    parameters = [cert_type, Peer_ip, cert_format, len(data), data]
                    importcert = initial.CImportCert(parameters)
                    status = importcert.SendAndReceive()
                    ##print "44444444444444"
                    if status != 0:
                        ##print "5555555555555555"
                        if(status == -2):
                            AlertInfo = SwitchErrorCode(status)
                        else:
                            AlertInfo = "证入导入失败"
                        db.session.close()
                        page = request.args.get('page',1, type=int)
                        pagination=Cipermachine.query.paginate(page,per_page=15,error_out=False)
                        cipermachine = pagination.items
                        total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
                        viewfunc = ".user2"
                        return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo=AlertInfo)
                    else:  
                        ##print "66666666666666666"
                        machinenumber = request.form['machinenumber']
                        province =request.form['first']
                        city = request.form['second']
                        part = request.form['third']
                        fourth = request.form['fourth']
                        manufacture = request.form['manufacture']
                        isonline = 1
                        spingtime = 0
                        discription = request.form['discription']
                        lock1.acquire()
                        equipment = Cipermachine(ip, machinenumber, province, city, part, fourth, manufacture, isonline,spingtime, discription,cerstyle)
                        db.session.add(equipment)
                        db.session.commit()
                        lock1.release()
                        cert = UploadCertificates.query.filter_by(certname=filename).first()
                        if(cert == None):
                            cert = UploadCertificates(filename)
                            db.session.add(cert)                        
                        #cert = UploadCertificates(filename)
                        #db.session.add(cert)
                        db.session.commit()
                        rank = "重要"
                        now = int(time.time())
                        name = session['username']
                        style = "LOG_WARNING"
                        content = "添加密码机"
                        log = Terminallogs(rank,now,name,style,content)
                        db.session.add(log)
                        db.session.commit()

                        if manufacture == "兴唐":
                            AddPrivateStatus(ip)
                        else:
                            AddCommonStatus(ip)

                        tree = Tree(province,city,part,fourth)
                        record = Tree.query.filter_by(province=province,city=city,part=part,fourth=fourth).first()
                        if record == None:
                            db.session.add(tree)
                            db.session.commit()
                            db.session.close()
                            return redirect('/equipment')
                        else:
                            return redirect('/equipment')
                else:
                    page = request.args.get('page',1, type=int)
                    pagination=Cipermachine.query.paginate(page,per_page=15,error_out=False)
                    cipermachine = pagination.items
                    total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
                    viewfunc = ".user2"
                    return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo="证书格式不正确，请重新选择！")
        else:
            page = request.args.get('page',1, type=int)
            pagination=Cipermachine.query.paginate(page,per_page=15,error_out=False)
            cipermachine = pagination.items
            total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
            viewfunc = ".user2"
            return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo="此IP已经存在，请重新输入！")

    @app.route('/equipment/delete', methods=['POST'])
    def delete_equipment():
        print "##########delete_equipment#########"
        machinenumbers= request.form['choosemachinenumber'].encode('utf-8').strip(',').split(',')
        lock1.acquire()
        for machine in machinenumbers:
            equipment = Cipermachine.query.filter_by(id=int(machine)).first()
            ### 删除前置机中的证书
            if equipment.encrypttype == 1:
                deletefilename = "ecc_" + equipment.ip
            else:
                deletefilename = equipment.ip
            deletecert = initial.CDeleteCert([deletefilename])
            status = deletecert.SendAndReceive()
            if status == -2:  ##除了连接超时，其他的都认为是正确的
                return str(status)
            if equipment.manufacture == "兴唐":
                status = models.DPrivateEquipmentCommonInfo.query.filter_by(id=int(machine)).all()
                linkinfo = models.DPrivateEquipmentLinkInfo.query.filter_by(id=int(machine)).all()
                if linkinfo != None:
                    for l in linkinfo:
                        db.session.delete(l)
            else:
                status = EquipmentsStatus.query.filter_by(id=int(machine)).all()

            if status != None:
                for s in status:
                    db.session.delete(s)

            db.session.delete(equipment)
            db.session.commit()
            rank = "重要"
            now = int(time.time())
            name = session['username']
            style = "LOG_WARNING"
            content = "删除密码机"
            log = Terminallogs(rank,now,name,style,content)
            db.session.add(log)
            db.session.commit()
            db.session.close()
        lock1.release()
        return '0'

    @app.route('/equipment/<int:id>/edit', methods=['POST'])
    def edit_equipment(id):
        eip = request.form['ip']
        legal1 = check_ip(eip)
        if legal1 == True:
            record = Cipermachine.query.filter_by(ip=eip).all()
            if len(record)-1 <= 0:
                eprovince = request.form['province']
                ecity = request.form['city']
                epart = request.form['part']
                efourth = request.form['fourth']
                if eprovince == "":
                    return "-3"
                else:
                    if ecity == "" and (epart != "" or efourth !=""):
                        return "-3"
                    else:
                        if epart == "" and efourth != "":
                            return "-3"
                        else:
                            equipment = Cipermachine.query.filter_by(id=id).first()
                            manufact = request.form['manufacture'].encode('utf8')

                            if (manufact !="兴唐") != (equipment.manufacture != "兴唐"):
                                print "@@@@@@@@@@@@manufact != equipment.manufacture:"
                                if equipment.manufacture == "兴唐":
                                    status = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
                                    #db.session.delete
                                    AddCommonStatus(eip)
                                else:
                                    status = EquipmentsStatus.query.filter_by(id=id).first()
                                    AddPrivateStatus(eip)
                                if status != None:
                                    db.session.delete(status)
                                    db.session.commit()
                            lock1.acquire()
                            equipment.ip = request.form['ip']
                            equipment.machinenumber = request.form['machinenumber']
                            equipment.province = request.form['province']
                            equipment.city = request.form['city']
                            equipment.part = request.form['part']
                            equipment.manufacture = request.form['manufacture']
                            equipment.fourth = request.form['fourth']
                            equipment.discription = request.form['discription']
                            db.session.add(equipment)
                            db.session.commit()
                            db.session.close()
                            lock1.release()
                            rank = "重要"
                            now = int(time.time())
                            name = session['username']
                            style = "LOG_WARNING"
                            content = "修改密码机基本信息"
                            log = Terminallogs(rank,now,name,style,content)
                            db.session.add(log)
                            db.session.commit()
                            tree = Tree(eprovince,ecity,epart,efourth)
                            record = Tree.query.filter_by(province=eprovince,city=ecity,part=epart,fourth=efourth).first()
                            if record == None:
                                db.session.add(tree)
                                db.session.commit()
                                return '1'
                            else:
                                return '1'
            else:
                return "-4"
        else:
            return "-3"

    @app.route('/equipment/replacecert',methods=['POST'])
    def replace_cert():
        page = request.args.get('page',1, type=int)
        pagination=Cipermachine.query.paginate(page,per_page=15,error_out=False)
        cipermachine = pagination.items
        total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
        viewfunc = ".user2"
        Peer_ip = request.form['peer_ip'].encode('utf-8').strip()
        #id = int(request.form['id'])
        machine = Cipermachine.query.filter_by(ip=Peer_ip).first()
        #print "########## Peer_ip = ",Peer_ip
        #print "########## id = ", id
        files = request.files.getlist('files[]')            
        for f in files:
            if f and allowed_file(f.filename):
                filen = secure_filename(f.filename)
                filename = Peer_ip + '.der'
                if len(filen) <= 0:
                    continue
                cert_type_code = 5            
                cerstyle = int(request.form['cerstyle'])
                print "####### cerstyle = ",cerstyle
                readonly = 0
                cert_format = int(request.form['cert_format']) 
                cert_type = (cerstyle *16) + (readonly * 8) + cert_type_code
                #########
                deletefilename = Peer_ip

                if(cerstyle == 1):
                    deletefilename = Peer_ip
                    filename = "ecc_" + filename
                else:
                    deletefilename = "ecc_" + Peer_ip
                deletecert = initial.CDeleteCert([deletefilename])
                status = deletecert.SendAndReceive()
                if status == -2:  ##除了连接超时，其他的都认为是正确的
                    return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo="请求超时，请查看网络连接！")
                 
                filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                f.save(filepath)


                certfile = open(filepath, 'r')
                data = certfile.read()
                certfile.close()
                parameters = [cert_type, Peer_ip, cert_format, len(data), data]
                importcert = initial.CImportCert(parameters)
                status = importcert.SendAndReceive()
                print "\n"
                print filename
                print "\n"
                if status == 0:

                    machine.encrypttype = cerstyle
                    db.session.add(machine)
                    db.session.commit()

                    rank = "重要"
                    now = int(time.time())
                    name = session['username']
                    style = "LOG_WARNING"
                    content = "替换密码机证书"
                    log = Terminallogs(rank,now,name,style,content)

                    cert = UploadCertificates.query.filter_by(certname=filename).first()
                    if(cert == None):
                        cert = UploadCertificates(filename)
                        db.session.add(cert)
                    db.session.add(log)
                    db.session.commit()
                    AlertInfo = SwitchErrorCode(status)
                else:
                    AlertInfo = "证书导入错误！"
                return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo=AlertInfo)
            else:
                return render_template('equipment.html',viewfunc=viewfunc,pagination=pagination,cipermachines=cipermachine, lm_total=total_count, AlertInfo="证书格式不正确，请重新选择！")


    @app.route('/checkciper',methods=['POST','GET'])
    def checkciper():
        # if request . method == "POST" :
        sheng = request.form['sheng']
        shi = request.form['shi']
        fenqu = request.form['fenqu']
        name = request.form['name']
        sip = request.form['sip']
        four = request.form['four']
        manufacture = request.form['manufacture']
        pagination = Cipermachine.query.filter(Cipermachine.province.like("%" + sheng + '%'),\
            Cipermachine.city.like('%' + shi  + '%'), \
            Cipermachine.part.like('%' + fenqu  + '%'), \
            Cipermachine.machinenumber.like('%' + name + '%'),\
            Cipermachine.ip.like('%' + sip + '%'), \
            Cipermachine.manufacture.like('%' + manufacture+ '%'),\
            Cipermachine.fourth.like('%'+four+'%')).paginate(1,per_page=15,error_out=False)
        finalreault = pagination.items
        cipermachine = Cipermachine.query.all()
        total_count = db.session.query(db.func.count(Cipermachine.id)).first()[0]
        viewfunc = ".checkciper"
        return render_template('equipment.html', viewfunc=viewfunc,pagination=pagination,cipermachines=finalreault, machines=finalreault, lm_total=total_count, \
            ip=sip,province=sheng,city=shi,part=fenqu,fourth=four,name=name,manufacturer=manufacture)

    @app.route('/equipment/export',methods=['POST'])
    def equipment_export():
        machine = Cipermachine.query.all()
        with open('static/uploads/equipment.csv',"w") as f:
            f.write('序号,IP地址,名称,第一级,第二级,第三级,第四级,厂家,备注\r\n'.decode('utf-8').encode('GBK'))
            index = 1
            for temp in machine:
                f.write((str(index) + ',' +temp.ip + ',' + temp.machinenumber + ',' + temp.province + ',' + temp.city + ',' + temp.part + ',' +temp.fourth + ',' + temp.manufacture +',' + temp.discription + '\r\n' ).decode('utf-8').encode('GBK'))
            index +=1;
        return "0"

    @app.route('/log',methods=['GET'])
    def getlog():
        user3 = Users.query.filter_by(admin=3).first()
        if user3 != None and session.get('admin') == user3.admin:
            lmlog = LeadMachinelogs.query.all()
            

            page = request.args.get('page',1, type=int)
            pagination=Terminallogs.query.paginate(page,per_page=15,error_out=False)
            terlog = pagination.items
            viewfunc = ".getlog"

            for temp in terlog:
                x = time.localtime(temp.time)
                temp.time=time.strftime('%Y-%m-%d %H:%M:%S',x)
            for temp in lmlog:
                x = time.localtime(temp.time)
                temp.time=time.strftime('%Y-%m-%d %H:%M:%S',x)

            return render_template('log.html',viewfunc=viewfunc,pagination=pagination,terlogs=terlog,lmlogs=lmlog)
        else:
            return redirect('/')


    @app.route('/backuplog/systemlog',methods=['POST'])
    def backup_system_log():
        terlog = Terminallogs.query.all()
        for temp in terlog:
                x = time.localtime(temp.time)
                temp.time=time.strftime('%Y-%m-%d %H:%M:%S',x)

        with open('static/uploads/terminallogs.csv',"w") as f:
            f.write('序号,告警级别,时间,用户名,告警类型,内容表述\r\n'.decode('utf-8').encode('GBK'))
            index = 1
            for temp in terlog:
                f.write((str(index) + ',' +temp.rank + ',' + temp.time + ',' + temp.name + ',' + temp.style + ',' + temp.content + '\r\n' ).decode('utf-8').encode('GBK'))
            index +=1;
        return "0"

    @app.route('/backuplog/leadmachinelog',methods=['POST'])
    def backup_leadmachine_log():
        lmlog = LeadMachinelogs.query.all()
        for temp in lmlog:
                x = time.localtime(temp.time)
                temp.time=time.strftime('%Y-%m-%d %H:%M:%S',x)

        with open('static/uploads/lead_machinelogs.csv',"w") as f:
            f.write('序号,告警级别,时间,用户名,告警类型,内容表述\r\n'.decode('utf-8').encode('GBK'))
            index = 1
            for temp in lmlog:
                f.write((str(index) + ',' +temp.rank + ',' + temp.time + ',' + temp.name + ',' + temp.style + ',' + temp.content + '\r\n' ).decode('utf-8').encode('GBK'))
            index +=1;
        return "0"

    @app.route('/checklog',methods=['POST'])
    def checklog():
        level=request.form['level']
        if level=="全部":
            level=""
        starttime=request.form['starttime']
        if starttime=="":
            starttime="0"
        else:
            tmpstarttime=int(time.mktime(time.strptime(request.form['starttime'], "%Y-%m-%d %H:%M")))
            starttime=str(tmpstarttime)
        endtime=request.form['endtime']
        if endtime=="":
            endtime="3462060952"
        else:
            tmpendtime=int(time.mktime(time.strptime(request.form['endtime'], "%Y-%m-%d %H:%M")))
            endtime=str(tmpendtime)
        username=request.form['username']
        logtype=request.form['logtype']
        if logtype=="全部":
            logtype=""
        keyword=request.form['keyword']
        results=db.engine.execute("select * from terminallogs where time>=" + str(starttime) + " and time<=" + str(endtime) +" and name like+ '%%"+str(username)+"%%'" + "and rank like+ '%%" + str(level) + "%%'" + "and style like+ '%%" + str(logtype) + "%%'" "and content like+ '%%" + str(keyword) + "%%'")
        finalreault = []
        for result in results:
            tempresult = Terminallogs(result.rank, result.time, result.name, result.style, result.content)
            finalreault.append(tempresult)
        for temp in finalreault:
            x = time.localtime(result.time)
            temp.time=time.strftime('%Y-%m-%d %H:%M:%S',x)
        lmlog=LeadMachinelogs.query.all()
        return render_template('log.html',terlogs=finalreault,lmlogs=lmlog)

    @app.route('/clean/systemlog',methods=['POST'])
    def clean_syslog():
        sql1 = "truncate table terminallogs"
        DeleteData(sql1)
        return "0"

    @app.route('/statistics',methods=['GET','POST'])
    def getstatistics():
        if request.method == 'GET':
            user3 = Users.query.filter_by(admin=3).first()
            if user3 != None and session.get('admin') == user3.admin:
                machinestatus = EquipmentsStatus.query.order_by(EquipmentsStatus.id.asc()).all()
                commonips = []
                for machinestate in machinestatus:
                    machineip = Cipermachine.query.filter_by(id = machinestate.id).first()
                    commonips.append([machineip,machinestate])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.order_by(models.DPrivateEquipmentCommonInfo.id.asc()).all()
                privateips = []
                
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=commonips,machines=machinestatus,result2s=privateips,privatemachines=privatemachinestatus)
            else:
                return redirect('/')
        if request.method == 'POST':
            choices = request.form['choices']
            machinestatistic = EquipmentsStatus.query.all()
            privatemachinestatistic = models.DPrivateEquipmentCommonInfo.query.all()
            if choices == "状态正常":
                machines = EquipmentsStatus.query.filter_by(status=0).all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.filter_by(work_status=0).all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "状态不正常":
                machines = EquipmentsStatus.query.filter_by(status=1).all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.filter_by(work_status=1).all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "安全模式":
                machines = EquipmentsStatus.query.filter_by(workmodel=0).all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.filter_by(work_status=0).all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "旁路模式":
                machines = EquipmentsStatus.query.filter_by(workmodel=2).all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.filter_by(work_status=2).all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "主装置":
                machines = EquipmentsStatus.query.filter_by(sign=1).all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "从装置":
                machines = EquipmentsStatus.query.filter_by(sign=0).all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "单机方式":
                machines = EquipmentsStatus.query.all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.filter_by(isstandalone=1).all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            
            elif choices == "主备方式":
                machines = EquipmentsStatus.query.all()
                normalip = []
                for machine in machines:
                    machineip = Cipermachine.query.filter_by(id = machine.id).first()
                    normalip.append([machineip,machine])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.filter_by(isstandalone=0).all()
                privateips = []
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=normalip,machines=machinestatistic,result2s=privateips,privatemachines=privatemachinestatistic,choices=choices)
            elif choices == "查看全部":
                machinestatus = EquipmentsStatus.query.order_by(EquipmentsStatus.id.asc()).all()
                commonips = []
                for machinestate in machinestatus:
                    machineip = Cipermachine.query.filter_by(id = machinestate.id).first()
                    commonips.append([machineip,machinestate])

                privatemachinestatus = models.DPrivateEquipmentCommonInfo.query.order_by(models.DPrivateEquipmentCommonInfo.id.asc()).all()
                privateips = []
                
                for privatestate in privatemachinestatus:
                    privateip = Cipermachine.query.filter_by(id = privatestate.id).first()
                    privateips.append([privateip,privatestate])

                return render_template('statistics.html',results=commonips,machines=machinestatus,result2s=privateips,privatemachines=privatemachinestatus)

            else:
                return redirect("/")

    @app.route('/privatecenter',methods=['GET'])
    def privateinfo():
        uid = session.get('uid')
        user = Users.query.filter_by(ukeyid=uid).first()
        if user != None:
            return render_template('privatecenter.html' , user = user)
        else:
            return redirect("/")

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect('/')

    @app.route('/adminlogout', methods=['GET'])
    def adminlogout():
        flag = request.args.get('flag')
        admin = Admin.query.filter_by(admin=0).first()
        admin.flag = flag
        db.session.commit()
        session.clear()
        return redirect('/home')

    @app.route('/certificate',methods=['GET'])
    def certificate():
        IiI1i = Users . query . filter_by ( admin = 2 ) . first ( )
        if IiI1i != None and session . get ( 'admin' ) == IiI1i . admin :
            certificates = models.UploadCertificates.query.all()

            page = request.args.get('page',1, type=int)
            pagination=UploadCertificates.query.paginate(page,per_page=15,error_out=False)
            terlog = pagination.items
            viewfunc = ".certificate"

            return render_template('certificate.html',certs = certificates, viewfunc=viewfunc,pagination=pagination,terlogs=terlog)
        else:
            return redirect('/')


    @app.route('/serachcert',methods=['POST'])
    def findcert():
        ip = request.form['sip']
        finalresult = models.UploadCertificates.query.filter(models.UploadCertificates.certname.like('%' + ip  + '%'))
        return render_template('certificate.html',certs=finalresult)


    @app.route('/user', methods=['GET'])
    def users():
        user1 = Users.query.filter_by(admin=1).first()
        if user1 != None and session.get('admin') == user1.admin:
            user = Users.query.all()
            userselect = Users.query.filter_by(pk="").all()
            length = len(userselect)
            total_count = db.session.query(db.func.count(Users.id)).first()[0]
            syscount = len(Users.query.filter_by(admin=1).all())
            safecount = len(Users.query.filter_by(admin=2).all())
            auditcount = len(Users.query.filter_by(admin=3).all())
            return render_template('user.html', users=user, count=total_count, syscount=syscount, safecount=safecount, auditcount=auditcount,userselect = userselect , length = length)
        else:
            return redirect('/')

    @app.route('/user/new', methods=['POST'])
    def create_user():

        status = ukey.m_ukey_prepare()
        if status != 0:
            return str(status)
        else:
            #print "@@@@@@@@@@@@@@@@@@@@"
            uid = session['uid']
            status66 = ukey.m_ukey_cycle_check(uid)
            if status66 == 0:
                return "10"
            else:
                name = request.form['name'].encode('utf-8')
                epassword1 = request.form['p1']
                epassword2 = request.form['p2']
                password1 = base64.decodestring(epassword1)
                password2 = base64.decodestring(epassword2)
                style = request.form['style']
                if style == "0":
                    admin="1"
                elif style == "1":
                    admin="2"
                elif style == "2":
                    admin="3"
                country = "中国"
                province = request.form['province'].decode('utf-8').encode('gbk')
                city = request.form['city'].decode('utf-8').encode('gbk')
                organ = request.form['organ'].encode('utf-8')
                depart = request.form['depart'].encode('utf-8')
                email = request.form['email'].encode('utf-8')
                record = Users.query.filter_by(name=request.form['name']).first()

                if record == None:
                    if password1 != password2:
                        print "33333333333333333"
                        return "3"
                    else:
                        status44 = ukey.m_ukey_get_info()
                        result = status44['r']
                        if result != 0:
                            print result,result,result
                            return str(result)
                        else:
                            ukeyid = status44['id_ptr'].split("\x00")[0]
                            record2 = Users.query.filter_by(ukeyid=ukeyid).first()
                            if record2 == None:
                                status2 = ukey.m_ukey_init(name,password1)
                                parameters = [country,province,city,organ,depart,name,email,status2['pk_ptr'],status2['id_ptr']]
                                initialusbkey = initial.InitialUkey(parameters)
                                Status = initialusbkey.SendAndReceive()
                                if Status == 0:
                                    losesign = True
                                    ukeyid = status2['id_ptr'].split('\x00')[0]
                                    ukeycert = ukeyid + '.pem'
                                    pk = ""
                                    user = Users(name, admin, epassword1, ukeyid, ukeycert, style, pk, losesign)
                                    db.session.add(user)
                                    rank = "普通"
                                    now = int(time.time())
                                    name = session['username']
                                    style = "LOG_INFO"
                                    content = "添加用户"
                                    log = Terminallogs(rank,now,name,style,content)
                                    db.session.add(log)
                                    db.session.commit()
                                    db.session.close()
                                    print status,status,status
                                    return str(Status)
                                else:
                                    print "-4-4-44-4-"
                                    return "-4"
                            else:
                                print "11111111111111"
                                return "1"
                else:
                    return "1234"

    @app.route('/user/newcert', methods=['POST'])
    def upload_userfile():
        username = request.form['name']
        files = request.files.getlist('files[]')             
        for f in files:
            filen = secure_filename(f.filename)
            user = Users.query.filter_by(name=username).first()
            filename = user.ukeyid + '.der'
            if len(filename) <= 0:
                continue
            filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
            f.save(filepath)
            certfile = open(filepath, 'r')
            data = certfile.read()
            certfile.close()
            user.pk = filename
            db.session.add(user)
            db.session.commit()
            rank = "重要"
            now = int(time.time())
            name = session['username']
            style = "LOG_NOTICE"
            content = "证书绑定用户"
            log = Terminallogs(rank,now,name,style,content)
            db.session.add(log)
            db.session.commit()
            db.session.close()
            return redirect('/user')


    @app.route('/user/<int:id>/delete', methods=['POST'])
    def delete_user(id):
        user=Users.query.filter_by(id=id).first()
        name = session['username']
        if name == user.name:
            return "5"
        else:
            db.session.delete(user)
            db.session.commit()
            rank = "重要"
            now = int(time.time())
            name = session['username']
            style = "LOG_NOTICE"
            content = "删除用户"
            log = Terminallogs(rank,now,name,style,content)
            db.session.add(log)
            db.session.commit()
            db.session.close()
            return '0'

    @app.route('/user/xiugai/<int:id>', methods=['POST'])
    def updata_user(id):
        status = ukey.m_ukey_prepare()
        if status != 0:
            return str(status)
        else:
            name = request.form['name']
            user = Users.query.filter_by(name=name).first()
            enewpassword1 = request.form['enew1']
            enewpassword2 = request.form['enew2']
            newpassword1 = base64.decodestring(enewpassword1)
            newpassword2 = base64.decodestring(enewpassword2)
            username = session['username']
            if newpassword1 == "" and newpassword2 == "":
                if name == username:
                    return "6"
                else:
                    newstyle = request.form['style_edit']
                    user.style = newstyle
                    if newstyle == "0":
                        user.admin="1"
                    elif newstyle == "1":
                        user.admin="2"
                    elif newstyle == "2":
                        user.admin="3"
                    db.session.add(user)
                    db.session.commit()
                    rank = "重要"
                    now = int(time.time())
                    name = session['username']
                    style = "LOG_NOTICE"
                    content = "修改用户权限"
                    log = Terminallogs(rank,now,name,style,content)
                    db.session.add(log)
                    db.session.commit()
                    db.session.close()
                    return "0"
            elif newpassword1 != "" and newpassword2 != "":
                if newpassword1 != newpassword2:
                    return "3"
                else:
                    if name == username:
                        return "7"
                    else:
                        if len(newpassword1) <8:
                            return "11"
                        else:
                            uid = session['uid']
                            status66 = ukey.m_ukey_cycle_check(uid)
                            if status66 == 0:
                                return "12"
                            else:
                                dpassword = base64.decodestring(user.password)   
                                status = ukey.m_modify_ukey_pwd(user.ukeyid,dpassword,newpassword1)
                                if status != 0:
                                    return str(status)
                                else:
                                    user.name = request.form['name']
                                    user.password = enewpassword1
                                    newstyle = request.form['style_edit']
                                    user.style = newstyle
                                    if newstyle == "0":
                                        user.admin="1"
                                    elif newstyle == "1":
                                        user.admin="2"
                                    elif newstyle == "2":
                                        user.admin="3"
                                    db.session.add(user)
                                    db.session.commit()
                                    rank = "重要"
                                    now = int(time.time())
                                    name = session['username']
                                    style = "LOG_NOTICE"
                                    content = "修改用户"
                                    log = Terminallogs(rank,now,name,style,content)
                                    db.session.add(log)
                                    db.session.commit()
                                    db.session.close()
                                    return "13"
            else:
                return "4"

    @app.route('/user/lose',methods=['POST'])
    def user_lose():
        user=Users.query.filter_by(id=request.form['id']).first()
        name = session['username']
        if name == user.name:
            return "14"
        else:
            user.losesign = False
            db.session.add(user)
            db.session.commit()
            rank = "重要"
            now = int(time.time())
            name = session['username']
            style = "LOG_NOTICE"
            content = "挂失用户"
            log = Terminallogs(rank,now,name,style,content)
            db.session.add(log)
            db.session.commit()
            db.session.close()
            return "0"

    @app.route('/user/cancellose',methods=['POST'])
    def cancel_lose():
        user=Users.query.filter_by(id=request.form['id']).first()
        name = session['username']
        if name == user.name:
            return "9"
        else:
            if user.losesign == False:
                user.losesign = True
                db.session.add(user)
                db.session.commit()
                rank = "重要"
                now = int(time.time())
                name = session['username']
                style = "LOG_NOTICE"
                content = "撤销挂失"
                log = Terminallogs(rank,now,name,style,content)
                db.session.add(log)
                db.session.commit()
                db.session.close()
                return "0"
            else:
                return "-2"


    @app.route('/user/unband',methods=['POST'])
    def user_unband():
        user=Users.query.filter_by(id=request.form['id']).first()
        name = session['username']
        if name == user.name:
            return "8"
        else:
            if user.pk != "":
                user.pk = ""
                db.session.add(user)
                db.session.commit()
                rank = "重要"
                now = int(time.time())
                name = session['username']
                style = "LOG_NOTICE"
                content = "撤销绑定"
                log = Terminallogs(rank,now,name,style,content)
                db.session.add(log)
                db.session.commit()
                db.session.close()
                return "0"
            else:
                return "-3"

    @app.route('/user/privateedit',methods=['POST'])
    def private_user_edit():
        name = request.form['name']
        eoldpassword = request.form['eold']
        oldpassword = base64.decodestring(eoldpassword)
        user = Users.query.filter_by(name=name).first()
        dpassword = base64.decodestring(user.password)
        if oldpassword != dpassword:
            return "5"
        else:
            enewpassword1 = request.form['enew']
            newpassword1 = base64.decodestring(enewpassword1)
            status = ukey.m_modify_ukey_pwd(user.ukeyid,dpassword,newpassword1)
            if status != 0:
                return str(status)
            else:
                user.name = name
                user.password = enewpassword1
                db.session.add(user)
                db.session.commit()
                return '0'

##  18条标准协议

##  1、查询装置状态及重启装置
    @app.route('/operation/commonequipment/<int:id>',methods=['POST'])
    def operation_common_equipment(id):
        sql2 = "truncate table channel_number"
        DeleteData(sql2)
        sql3 = "truncate table channel_status"
        DeleteData(sql3)
        sql4 = "truncate table channel_security_strategy"
        DeleteData(sql4)
        machine = Cipermachine.query.filter_by(id=id).first()
        alert = ''
        queryequipmentstatus = operationequipment.CQueryEquipmentStatus(id,machine.ip,machine.encrypttype)
        status1 = queryequipmentstatus.SendAndReceive()       
        if status1 != 0:
            alert = alert + '获取隧道信息失败！\n' 
            equipmentstatus = EquipmentsStatus.query.filter_by(id = id).first()
            equipmentstatus.status = 1
            db.session.add(equipmentstatus)
            db.session.commit()      
        if status1 == -2:
            alert = "请求超时，请查看网络连接！"
            return alert
        querychannel = operationequipment.QueryChannel(id,machine.ip,machine.encrypttype)
        status2 = querychannel.SendAndReceive()

        if status2 != 0:
            alert = alert + '查询已有隧道失败\n'
        if len(alert) == 0:
            equipmentstatus = EquipmentsStatus.query.filter_by(id=id).first()
            equipmentstatus.status = 0
            db.session.add(equipmentstatus)
            db.session.commit()
            return "0"
        else:
            return alert

    @app.route('/commonequipment/<int:id>', methods=['GET','POST'])
    def common_equipment(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            machine = Cipermachine.query.filter_by(id=id).first()
            if id and request.method == 'GET':
                status = EquipmentsStatus.query.filter_by(id=id).first()                
                return render_template('standard.html',status=status, machine=machine)
            if id and request.method == 'POST':
                ip = machine.ip.encode('utf-8')
                queryequipmentstatus = operationequipment.CQueryEquipmentStatus(id,ip)
                status = queryequipmentstatus.SendAndReceive()
                return str(status)
        else:
            return redirect('/')

    @app.route('/commonequipment/restartmachine/<int:id>',methods=['POST'])
    def restart_machine(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip.encode('utf-8')
        restartmachine = operationequipment.CRestartMachine(id,ip,machine.encrypttype)
        status = restartmachine.SendAndReceive()
        return str(status)

##  2、证书管理
    @app.route('/commonequipment/stancertmanage/<int:id>', methods=['GET'])
    def standard_certmanage(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            machine = Cipermachine.query.filter_by(id=id).first()
            return render_template('stancertmanage.html',machine=machine)
        else:
            return redirect('/')

    @app.route('/commonequipment/stancertmanage/replace/<int:id>',methods=['POST'])
    def replace_certificate(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        files = request.files.getlist('files[]')
        peer_ip = request.form['ip'].encode('utf-8')              
        for f in files:
            if f and allowed_file(f.filename): 
                filen = secure_filename(f.filename)
                filename = peer_ip + '.der'
                if len(filen) <= 0:
                    continue
                filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                f.save(filepath)
                
                certfile = open(filepath,'r')
                data = certfile.read()
                certfile.close()
                parameters = [peer_ip, data]
                replacecert = operationequipment.CReplaceCert(id, machine.ip, parameters,machine.encrypttype)
                status = replacecert.SendAndReceive()
                if status == 0:
                    certificate = Certificates(id,peer_ip)
                    db.session.add(certificate)
                    db.session.commit()
                    cert = UploadCertificates.query.filter_by(certname=filename).first()
                    if(cert == None):
                        cert = UploadCertificates(filename)
                        db.session.add(cert)                   
                    #cert = UploadCertificates(filename)
                    #db.session.add(cert)
                    db.session.commit()
                AlertInfo = SwitchErrorCode(status)
                return render_template('stancertmanage.html',machine=machine,AlertInfo=AlertInfo)
            else:
                return render_template('stancertmanage.html',machine=machine,AlertInfo="上传文件格式不对，请重新上传!")

##  3、隧道管理
### change managment GET
    @app.route('/commonequipment/stanchannel/<int:id>', methods=['GET'])
    def standard_certchannel(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            page = request.args.get('page',1,type=int)
            machine = Cipermachine.query.filter_by(id=id).first()
            certificate = Certificates.query.filter_by(id=id).all()
            per_pagecount = 10
            pagination = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).paginate(page,per_page=per_pagecount,error_out=False)
            channels = pagination.items
            flag = False
            for channel in channels:
                if channel.uip == None:
                    flag = True
                    ip = machine.ip.encode('utf-8')
                    querychannelstatus = operationequipment.CQueryChannelStatus(id,ip,[channel.channelnumber],machine.encrypttype)
                    status = querychannelstatus.SendAndReceive()
                    if status != 0:
                        break
            if flag:
                pagination = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).paginate(page, per_page=per_pagecount, error_out=False)
                channels = pagination.items
            total_channel = ChannelStatus.query.filter_by(id=id).count()
            if total_channel == 0:
                pagination = None
            return render_template('stanchannel.html',machine=machine,channel=channels,channel_total=total_channel,pagination=pagination,certs = certificate)
        else:
            return redirect('/')


    @app.route('/commonequipment/stanchannel/pagination',methods=['GET'])
    def standard_pagination_channel():
        id = request.args.get('machineid',1,type=int)
        page = request.args.get('page',1,type=int)
        machine = Cipermachine.query.filter_by(id=id).first()
        certificate = Certificates.query.filter_by(id=id).all()
        per_pagecount = 10
        pagination = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).paginate(page, per_page=per_pagecount, error_out=False)
        channels = pagination.items
        flag = False
        for channel in channels:
            if channel.uip == None:
                flag = True
                ip = machine.ip.encode('utf-8')
                querychannelstatus = operationequipment.CQueryChannelStatus(id, ip, [channel.channelnumber],machine.encrypttype)
                status = querychannelstatus.SendAndReceive()
                if status != 0:
                    break
        if flag:
            pagination = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).paginate(page, per_page=per_pagecount, error_out=False)
            channels = pagination.items

        total_channel = ChannelStatus.query.filter_by(id=id).count()
        return render_template('stanchannel.html',machine=machine,channel=channels,channel_total=total_channel,pagination=pagination,certs = certificate)


### query channel
    @app.route('/commonequipment/querychannel/<int:id>',methods=['POST'])
    def query_channel(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip.encode('utf-8')
        querychannel = operationequipment.QueryChannel(id,ip,machine.encrypttype)
        status = querychannel.SendAndReceive()
        return str(status)
        

### add channel
    @app.route('/commonequipment/addchannel/<int:id>',methods=['POST'])
    def add_channel(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        oip = request.form['oip']
        eip = request.form['eip']
        if oip == '':
            return "-4"
        if eip == '':
            eip = u'0.0.0.0'
        legal1 = check_ip(oip)
        if legal1 == 0:
            return "-3"
        else: 
            legal2 = check_ip(eip)
            if legal2 == 0:
                return "-3"
            else:
                workmodel = request.form['cworkmodel']
                parameter = [oip.encode('utf-8'), eip.encode('utf-8'), int(workmodel.encode('utf-8'))]
                ip = machine.ip.encode('utf-8')
                addchannel = operationequipment.AddChannel(id, ip, parameter,machine.encrypttype)
                status = addchannel.SendAndReceive()
                if status ==  0:
                    querychannel = operationequipment.QueryChannel(id,ip,machine.encrypttype)
                    querychannel.SendAndReceive()
                return str(status)

### query channel status
    @app.route('/commonequipment/querychannelstatus/<int:id>',methods=['POST'])
    def query_channel_status(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip.encode('utf-8')
        channelnumber = request.form['choosechannelnumber']
        parameter = [int(channelnumber.encode('utf-8'))]
        querychannelstatus = operationequipment.CQueryChannelStatus(id, ip, parameter,machine.encrypttype)
        status = querychannelstatus.SendAndReceive() 
        return str(status)

### set channel work model
    @app.route('/commonequipment/setchannelworkmodel/<int:id>',methods=['POST'])
    def set_channel_wrokmodel(id):
        channelnumber = request.form['choosechannelnumber']
        workmodel = request.form['cworkmodel']
        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip.encode('utf-8')
        parameter = [int(workmodel.encode('utf-8')), int(channelnumber.encode('utf-8')) ]
        querychannelstatus = operationequipment.CSetChannelWorkmodel(id, ip, parameter,machine.encrypttype)
        status = querychannelstatus.SendAndReceive()
        return str(status)       

### Reset Channel
    @app.route('/commonequipment/resetchannel/<int:id>',methods=['POST'])
    def reset_channel(id):
        channelnumber = request.form['choosechannelnumber']
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        parameter = [int(channelnumber.encode('utf-8'))]

        resetchannel = operationequipment.CResetChannel(id, ip, parameter,machine.encrypttype)
        status = resetchannel.SendAndReceive()
        return str(status)

### delete channel
    @app.route('/commonequipment/deletechannel/<int:id>',methods=['POST'])
    def delete_channel(id):
        channelnumber = request.form['choosechannelnumber']
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        parameter = [int(channelnumber.encode('utf-8'))]

        resetchannel = operationequipment.CDeleteChannel(id, ip, parameter,machine.encrypttype)
        status = resetchannel.SendAndReceive()
        return str(status)

##  4、策略管理
### stragety management GET
    @app.route('/commonequipment/stanstrategy', methods=['GET'])
    def standard_stragtegy():
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            id = request.args.get("machineid",1,type=int)
            number = request.args.get("channelid",1,type=int)
            page = request.args.get("page",1,type=int)
            strategy = DSecurityStrategy.query.filter_by(id=id, channelnumber=number).order_by(DSecurityStrategy.strategynumber.asc()).all()
            machine = Cipermachine.query.filter_by(id=id).first()
            selectnumbers = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).all()
            return render_template('stanstrategy.html',machine=machine,channel_number=number,strategies=strategy,selectnumbers=selectnumbers,page=page)
        else :
            return redirect ( '/' )

    @app.route('/commonequipment/stanstrategy/<int:id>', methods=['GET'])
    def standard_check_stragtegy(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            channelnumber = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).all()
            machine = Cipermachine.query.filter_by(id=id).first()
            return render_template('stanstrategy.html',machine=machine,selectnumbers=channelnumber)
        else:
            return redirect('/')

    @app.route('/commonequipment/stanstrategy/<int:id>/<int:number>',methods=['GET'])
    def standard_strategy_check(id,number):
        print "#############standard_strategy_check"
        IiI1i = Users . query . filter_by ( admin = 2 ) . first ( )
        if IiI1i != None and session . get ( 'admin' ) == IiI1i . admin :
            channelnumber = number
            machine = Cipermachine.query.filter_by(id = id).first()
            ip = machine.ip.encode('utf-8')
            parameter = [channelnumber]

            querysecuritystrategy = operationequipment.CQuerySecurityStrategy(id, ip, parameter,machine.encrypttype)
            status = querysecuritystrategy.SendAndReceive()
            selectnumbers = ChannelStatus.query.filter_by(id = id ).order_by(ChannelStatus.channelnumber.asc()).all()
            strategies = DSecurityStrategy . query . filter_by ( id = id , channelnumber = number ) . order_by ( DSecurityStrategy . strategynumber . asc ( ) ) . all ( )
            return render_template ('stanstrategy.html' , machine = machine , channel_number = number , strategies = strategies, selectnumbers = selectnumbers)
        else:
            return redirect('/')



### select channel number
    @app.route('/commonequipment/stanstrategy/select/<int:id>',methods=['POST'])
    def select_channel_number(id):
        selectchannelnumber = int(request.form['selectchannelnumber'])
        strategy = DSecurityStrategy.query.filter_by(id=id, channelnumber=selectchannelnumber).order_by(DSecurityStrategy.strategynumber.asc()).all()
        channelnumber = ChannelStatus.query.filter_by(id=id).order_by(ChannelStatus.channelnumber.asc()).all()
        machine = Cipermachine.query.filter_by(id=id).first()
        return render_template('stanstrategy.html',machine=machine,channel_number=selectchannelnumber,strategies=strategy,selectnumbers=channelnumber)

### query channel stragety
    @app.route('/commonequipment/querychannelstrategy/<int:id>/<int:number>',methods=['POST'])
    def query_channel_stragety(id,number):
        channelnumber = number
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        parameter = [channelnumber]

        querysecuritystrategy = operationequipment.CQuerySecurityStrategy(id, ip, parameter,machine.encrypttype)
        status = querysecuritystrategy.SendAndReceive()

        return str(status)

### add channle strategy
    @app.route('/commonequipment/addchannelstrategy/<int:id>/<int:number>',methods=['POST'])
    def add_channel_strategy(id,number):
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        channelnumber = number
        strategynumber = 0

        SrcIP = (request.form['sip1']).encode('utf-8')
        SrcIPMask = (request.form['sip2']).encode('utf-8')
        DstIP = (request.form['dip1'] ).encode('utf-8')        
        DstIPMask = (request.form['dip2']).encode('utf-8')

        Direction = int(request.form['destination'].encode('utf-8'))
        Protocol = int(request.form['protocol'].encode('utf-8'))
        Mode = int(request.form['workmodel'].encode('utf-8'))
        Reserved = 0

        SrcPortMin = int(request.form['sport1'].encode('utf-8'))
        SrcPortMax = int(request.form['sport2'].encode('utf-8'))
        DstPortMin = int(request.form['dport1'].encode('utf-8'))
        DstPortMax = int(request.form['dport2'].encode('utf-8'))

        legal1 = check_ip(SrcIP)
        legal2 = check_ip(SrcIPMask)
        legal3 = check_ip(DstIP)
        legal4 = check_ip(DstIPMask)
        if legal1 & legal2 & legal3 &legal4 == 0:
            return "-4"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(SrcIP))[0]
            ip2 = struct.unpack('!L',socket.inet_aton(SrcIPMask))[0]
            ip3 = struct.unpack('!L',socket.inet_aton(DstIP))[0]
            ip4 = struct.unpack('!L',socket.inet_aton(DstIPMask))[0]
            com1 = ip1 - ip2
            com2 = ip3 - ip4
            pare1 = SrcPortMin - SrcPortMax
            pare2 = DstPortMin - DstPortMax
            if com1 > 0 or com2 >0 or pare1>0 or pare2>0 or SrcPortMax > 65535 or DstPortMax > 65535:
                return "-3"
            else:
                parameter = [channelnumber, strategynumber, SrcIP, SrcIPMask, DstIP, DstIPMask, Direction,Protocol, Mode, Reserved, SrcPortMin,SrcPortMax, DstPortMin, DstPortMax]
                addchannelstrategy = operationequipment.CAddSecurityStrategy(id, ip, parameter,machine.encrypttype)
                status = addchannelstrategy.SendAndReceive()
                # if status != 0:
                #     return str(status)
                # querysecuritystrategy = operationequipment.CQuerySecurityStrategy(id, ip, [channelnumber],machine.encrypttype)
                # querysecuritystrategy.SendAndReceive()
                return str(status)

### edit channel strategy
    @app.route('/commonequipment/editchannelstrategy/<int:id>/<int:number>',methods=['POST'])
    def edit_channel_strategy(id,number):
        print "111111111111111111"
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        print "222222222222222"
        channelnumber = number
        strategynumber = int(request.form['choosestragetynumber'].encode('utf-8'))        

        SrcIP = request.form['sip1_edit'] .encode('utf-8')
        SrcIPMask = request.form['sip2_edit'] .encode('utf-8')
        DstIP = request.form['dip1_edit'] .encode('utf-8')        
        DstIPMask = request.form['dip2_edit'] .encode('utf-8')
        # print SrcIP, SrcIPMask, DstIP, DstIPMask
        Direction = int(request.form['destination_edit'].encode('utf-8'))
        Protocol = int(request.form['protocol_edit'].encode('utf-8'))
        Mode = int(request.form['workmodel_edit'].encode('utf-8'))
        Reserved = 0

        SrcPortMin = int(request.form['sport1_edit'].encode('utf-8'))
        SrcPortMax = int(request.form['sport2_edit'].encode('utf-8'))
        DstPortMin = int(request.form['dport1_edit'].encode('utf-8'))
        DstPortMax = int(request.form['dport2_edit'].encode('utf-8'))

        legal1 = check_ip(SrcIP)
        legal2 = check_ip(SrcIPMask)
        legal3 = check_ip(DstIP)
        legal4 = check_ip(DstIPMask)
        if legal1 & legal2 & legal3 &legal4 == 0:
            return "-4"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(SrcIP))[0]
            ip2 = struct.unpack('!L',socket.inet_aton(SrcIPMask))[0]
            ip3 = struct.unpack('!L',socket.inet_aton(DstIP))[0]
            ip4 = struct.unpack('!L',socket.inet_aton(DstIPMask))[0]
            com1 = ip1 - ip2
            com2 = ip3 - ip4
            pare1 = SrcPortMin - SrcPortMax
            pare2 = DstPortMin - DstPortMax
            if com1 > 0 or com2 >0 or pare1>0 or pare2>0 or SrcPortMax > 65535 or DstPortMax > 65535:
                return "-3"
            else:
                parameter = [channelnumber, strategynumber, SrcIP, SrcIPMask, DstIP, DstIPMask, Direction,Protocol, Mode, Reserved, SrcPortMin,SrcPortMax, DstPortMin, DstPortMax]
                modifysecuritystrategy = operationequipment.CModifySecurityStrategy(id, ip, parameter,machine.encrypttype)
                status = modifysecuritystrategy.SendAndReceive()
                # if status == 0:
                #     querysecuritystrategy = operationequipment.CQuerySecurityStrategy(id, ip, [channelnumber],machine.encrypttype)
                #     querysecuritystrategy.SendAndReceive()        
                return str(status)
                #return '0'

### delete channel strategy
    @app.route('/commonequipment/deletechannelstrategy/<int:id>/<int:number>', methods=['POST'])
    def delete_channel_strategy(id,number):
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        channelnumber = number
        strategynumber = int(request.form['cstragetynum'].encode('utf-8')) 
        parameter = [channelnumber,strategynumber]
        deletesecuritystrategy = operationequipment.CDeleteSecurityStrategy(id, ip, parameter,machine.encrypttype)
        status = deletesecuritystrategy.SendAndReceive()
        # if status == 0:
        #     querysecuritystrategy = operationequipment.CQuerySecurityStrategy(id, ip, [channelnumber],machine.encrypttype)
        #     querysecuritystrategy.SendAndReceive()        
        return str(status)

### copy channel strategy
    @app.route('/commonequipment/copychannelstrategy/<int:id>', methods=['POST'])
    def copy_channel_strategy(id):
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        channelnumber = int(request.form['channelnumber'],10)
        ##print channelnumber,"###########"
        strategynumber = 0
        
        SrcIP = request.form['sip1_edit'] .encode('utf-8')
        SrcIPMask = request.form['sip2_edit'] .encode('utf-8')
        DstIP = request.form['dip1_edit'] .encode('utf-8')        
        DstIPMask = request.form['dip2_edit'] .encode('utf-8')
        ##print SrcIP, SrcIPMask, DstIP, DstIPMask
        Direction = int(request.form['destination_edit'].encode('utf-8'))
        Protocol = int(request.form['protocol_edit'].encode('utf-8'))
        Mode = int(request.form['workmodel_edit'].encode('utf-8'))
        Reserved = 0

        SrcPortMin = int(request.form['sport1_edit'].encode('utf-8'))
        SrcPortMax = int(request.form['sport2_edit'].encode('utf-8'))
        DstPortMin = int(request.form['dport1_edit'].encode('utf-8'))
        DstPortMax = int(request.form['dport2_edit'].encode('utf-8'))

        legal1 = check_ip(SrcIP)
        legal2 = check_ip(SrcIPMask)
        legal3 = check_ip(DstIP)
        legal4 = check_ip(DstIPMask)
        if legal1 & legal2 & legal3 &legal4 == 0:
            return "-4"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(SrcIP))[0]
            ip2 = struct.unpack('!L',socket.inet_aton(SrcIPMask))[0]
            ip3 = struct.unpack('!L',socket.inet_aton(DstIP))[0]
            ip4 = struct.unpack('!L',socket.inet_aton(DstIPMask))[0]
            com1 = ip1 - ip2
            com2 = ip3 - ip4
            pare1 = SrcPortMin - SrcPortMax
            pare2 = DstPortMin - DstPortMax
            if com1 > 0 or com2 >0 or pare1>0 or pare2>0 or SrcPortMax > 65535 or DstPortMax > 65535:
                return "-3"
            else:
                parameter = [channelnumber, strategynumber, SrcIP, SrcIPMask, DstIP, DstIPMask, Direction,Protocol, Mode, Reserved, SrcPortMin,SrcPortMax, DstPortMin, DstPortMax]
                
                modifysecuritystrategy = operationequipment.CAddSecurityStrategy(id, ip, parameter,machine.encrypttype)
                status = modifysecuritystrategy.SendAndReceive()
                if status == 0:
                    querysecuritystrategy = operationequipment.CQuerySecurityStrategy(id, ip, [channelnumber],machine.encrypttype)
                    querysecuritystrategy.SendAndReceive()        
                return str(status)


##  5、日志管理
    @app.route('/commonequipment/stanlog/<int:id>', methods=['GET'])
    def standard_log(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            machine = Cipermachine.query.filter_by(id=id).first()
            return render_template('stanlog.html',machine=machine)
        else:
            return redirect('/')


    @app.route('/commonequipment/querylength/<int:id>', methods=['POST'])
    def query_log_length(id):
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        queryloglenth = operationequipment.CQueryLogLength(id, ip,machine.encrypttype)
        status, loglength = queryloglenth.SendAndReceive()
        return str(status)        

    @app.route('/commonequipment/readlog/<int:id>', methods=['GET'])
    def read_log(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            machine = Cipermachine.query.filter_by(id = id).first()
            ip = machine.ip.encode('utf-8')
            queryloglenth = operationequipment.CQueryLogLength(id, ip,machine.encrypttype)
            status1, loglength = queryloglenth.SendAndReceive()
            AlertInfo = ""
            if status1 != 0:
                AlertInfo = SwitchErrorCode(status1)
                return render_template('stanlog.html',machine=machine,AlertInfo=AlertInfo)
            page = 1 ## first page
            per_page = 15
            if loglength == 0:
                pages = 1
            else:
                pages = int((loglength - 1) / per_page) + 1
            has_prev = False
            has_next = (page < pages)
            class CPagination():
                def __init__(self, has_next, has_prev, pages, per_page,loglength,page):
                    self.has_prev = has_prev
                    self.has_next = has_next
                    self.pages = pages
                    self.per_page = per_page
                    self.loglength = loglength
                    self.page = page
            pagination = CPagination(has_next, has_prev, pages, per_page,loglength, page)
            if page == pages:
                readlog = operationequipment.CReadLog(id,machine.ip,[loglength - pages * per_page  + per_page, 1],machine.encrypttype)
                status,logs = readlog.SendAndReceive()
            else:
                readlog = operationequipment.CReadLog(id,machine.ip,[per_page,loglength - page * per_page + 1],machine.encrypttype)  
                status,logs = readlog.SendAndReceive()
            print logs
            if status != 0:
                AlertInfo = SwitchErrorCode(AlertInfo)      
            return render_template('stanlog.html',machine=machine, logs=logs[::-1], pagination=pagination, AlertInfo=AlertInfo)
        else:
            return redirect('/')        

    @app.route('/commonequipment/paginatelog', methods=['GET'])
    def stdpaginatelog():
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():

            id = request.args.get('machineid',1,type=int)
            per_page = 15
            machine = Cipermachine.query.filter_by(id=id).first()        
            page = request.args.get('page',1, type=int)

            loglength = request.args.get('loglength',0,type=int)
            if loglength == 0:
                pages = 1
            else:
                pages = int((loglength - 1) / per_page) + 1                
            has_prev = (pages > 1)
            has_next = (page < pages)
            class CPagination():
                def __init__(self, has_next, has_prev, pages, per_page, loglength, page):
                    self.has_prev = has_prev
                    self.has_next = has_next
                    self.pages = pages
                    self.per_page = per_page
                    self.loglength = loglength
                    self.page = page
            pagination = CPagination(has_next, has_prev, pages, per_page,loglength, page)
            if page == pages:
                readlog = operationequipment.CReadLog(id,machine.ip,[loglength - pages * per_page  + per_page, 1],machine.encrypttype)
                status,logs = readlog.SendAndReceive()
            else:
                readlog = operationequipment.CReadLog(id,machine.ip,[per_page,loglength - page * per_page + 1],machine.encrypttype)  
                status,logs = readlog.SendAndReceive()
            ooO0O0O0ooOOO = ""
            AlertInfo = ""
            if status != 0:
                AlertInfo = SwitchErrorCode(status)
            return render_template('stanlog.html',machine=machine, logs=logs[::-1], pagination=pagination,AlertInfo=AlertInfo)        
        else:
            return redirect('/')


## 62条私有协议

## 1、首页
    @app.route('/operation/privateequipment/<int:id>',methods=['POST'])
    def operation_private_equipment(id):
        sql5 = "truncate table private_channel_info"
        DeleteData(sql5)
        sql6 = "truncate table private_security_strategy"
        DeleteData(sql6)
        sql7 = "truncate table private_cert_info"
        DeleteData(sql7)
        machine = Cipermachine.query.filter_by(id=id).first()
        alert = ''           
        querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0],machine.encrypttype)
        status = querysystemconfigure.SendAndReceive()
        if(status != 0):
            equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
            if(equipmentstatus != None):

                equipmentstatus.work_status = 1
                db.session.add(equipmentstatus)
                db.session.commit()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert
        if status != 0:
            alert = alert + '获取链路1配置信息失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'
        querysystemconfigure2 = privatesystem.CQuerySystemInfo(id, machine.ip, [1],machine.encrypttype)
        status = querysystemconfigure2.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert        
        if status != 0:
            alert = alert +  '获取链路2配置信息失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'

        getstatsticscount = privatesystem.CGetStatisticsCount(id, machine.ip,machine.encrypttype)
        status = getstatsticscount.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert        
        if status != 0:
            alert = alert + '获取设备统计计数失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'
        querychannelinfo = privatechannel.CQueryChannelInfo(id,machine.ip,machine.encrypttype)
        status = querychannelinfo.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert        
        if status != 0:
            alert = alert + '获取隧道信息失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'
        if len(alert) == 0:
            # equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(keyid=id).first()
            # if(equipmentstatus != None):

            #     equipmentstatus.work_status = 0
            #     db.session.add(equipmentstatus)
            #     db.session.commit()
            return "0"
        else:
            return alert
        
    @app.route('/privateequipment/<int:id>', methods=['GET'])
    def operation_equipment(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            status = EquipmentsStatus.query.filter_by(id=id).first()
            machine = Cipermachine.query.filter_by(id=id).first()
            channels = models.DPrivateChannelInfo.query.filter_by(id=id).order_by(models.DPrivateChannelInfo.channelnumber).all()
            status = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
            status1 = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=0).first()
            status2 = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=1).first()
            return render_template('operationequipment.html',status=status, status1=status1, status2=status2, machine=machine,channels=channels)
        else:
            return redirect('/')

    @app.route('/privateequipment/querysystemconfigure/<int:id>', methods=['POST'])
    def query_system_configure(id):
        print "query system configure"
        machine = Cipermachine.query.filter_by(id=id).first()
        alert = ''           
        querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0],machine.encrypttype)
        status = querysystemconfigure.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert
        if status != 0:
           alert = alert + '获取链路1配置信息失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'
        querysystemconfigure2 = privatesystem.CQuerySystemInfo(id, machine.ip, [1],machine.encrypttype)
        status = querysystemconfigure2.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert
        if status != 0:
            alert = alert +  '获取链路2配置信息失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'

        getstatsticscount = privatesystem.CGetStatisticsCount(id, machine.ip,machine.encrypttype)
        status = getstatsticscount.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert
        if status != 0:
            alert = alert + '获取设备统计计数失败！ 错误原因：' +  SwitchErrorCode(status) +  '\n'
        getparainfo = privatesystem.CGetParameterInformation(id, machine.ip,machine.encrypttype)
        status = getparainfo.SendAndReceive()
        if status == -2:
            alert = "请求超时，请查看网络连接！"
            return alert
        if status != 0:
            alert = alert + '获取系统参数信息失败！错误原因：' +  SwitchErrorCode(status) +  '\n'
        if len(alert) == 0:
            return "0"
        else:
            return alert

    @app.route('/privateequipment/querychannel/<int:id>', methods=['POST'])
    def query_private_channel(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        querychannelinfo = privatechannel.CQueryChannelInfo(id,machine.ip,machine.encrypttype)
        status = querychannelinfo.SendAndReceive()
        return str(status)

## 2、证书管理
    @app.route('/privateequipment/privatecertmanage/import/<int:id>',methods=['GET'])
    def private_certmanage_import(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            machine = Cipermachine.query.filter_by(id=id).first()
            return render_template('privatecertmanage.html',machine=machine)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatecertmanage/manage/<int:id>',methods=['GET'])
    def private_certmanage(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin():
            machine = Cipermachine.query.filter_by(id=id).first()
            querycertlist = privatecert.CQueryCertList(id,machine.ip)
            status = querycertlist.SendAndReceive()
            certificates = DPrivateCertInfo.query.filter_by(id=id).all()
            return render_template('privatecertmanage2.html',machine=machine,certificates=certificates)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatecertmanage/import/<int:id>',methods=['POST'])
    def private_cert_import(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        Peer_ip = (request.form['ip']).encode('utf-8')
        cerstyle = int(request.form['cerstyle'])
        files = request.files.getlist('files[]')               
        for f in files:
            if f and allowed_file(f.filename):
                cert_type_code = int(request.form['cert_type'])
                filen = secure_filename(f.filename)
                if len(filen) <= 0:
                    continue
                if cert_type_code == 5:
                    filename = Peer_ip + '.der'
                elif cert_type_code == 1:
                    filename = 'DMS_' + Peer_ip + '.der'
                elif cert_type_code == 0:
                    filename = 'RA_ROOT.der'
                else :
                    filename = secure_filename(f.filename)
                if cerstyle == 1:
                    filename ='ecc_' + filename
                    #filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                    #f.save(filepath)
                    #else:
                    #filename = Peer_ip + '.der'
                    #filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                    #f.save(filepath)
                filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                f.save(filepath)    

                certfile = open(filepath, 'r')
                data = certfile.read()
                certfile.close()        
                #cerstyle = int(request.form['cerstyle'])
                #cert_type_code = int(request.form['cert_type'])
                try:
                    readonly = int(request.form['readonly'])
                except:
                    readonly = 0
                cert_type = (cerstyle *16) + (readonly * 8) + cert_type_code
                cert_format = int(request.form['cert_format'])
                print "###############cert_format = ",cert_format
                Peer_ip = (request.form['ip']).encode('utf-8')
                parameters = [cert_type, Peer_ip, cert_format, len(data), data]
                importcert = privatecert.CImportCert(id, machine.ip, parameters,machine.encrypttype)
                print "###############machine.encrypttype = ",machine.encrypttype
                status = importcert.SendAndReceive()
                if status != 0:
                    AlertInfo = "导入失败"
                else:
                    cert = UploadCertificates.query.filter_by(certname=filename).first()
                    if(cert == None):
                        cert = UploadCertificates(filename)
                        db.session.add(cert)                   
                    db.session.commit()
                    AlertInfo = "导入成功"
                return render_template('privatecertmanage.html',machine=machine,AlertInfo=AlertInfo)
            else:
                return render_template('privatecertmanage.html',machine=machine,AlertInfo="上传文件格式不对，请重新上传")
        ## query cert list 1.2.2
   
    @app.route('/privateequipment/querycertificationlist/<int:id>',methods=['POST'])
    def private_query_certlist(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip
        querycertlist = privatecert.CQueryCertList(id,ip,machine.encrypttype)
        status = querycertlist.SendAndReceive()
        return str(status)


    @app.route('/privateequipment/querycertification/<int:id>',methods=['POST'])
    def private_query_certification(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip
        choosecertip = request.form['choosecertip'].encode('utf-8')
        parameters = [choosecertip]
        querycert = privatecert.CQueryCert(id,ip,parameters,machine.encrypttype)
        status,info = querycert.SendAndReceive()
        info.update({"status":str(status)})
        return jsonify(info)

    @app.route('/privateequipment/deletecertification/<int:id>',methods=['POST'])
    def private_delete_certification(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        choosecertip = request.form['choosecertip'].encode('utf-8')
        deletecert = privatecert.CDeleteCert(id, machine.ip, [choosecertip],machine.encrypttype)
        status = deletecert.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/renamecertification/<int:id>',methods=['POST'])
    def private_rename_certification(id):
        oldname = request.form['oldname'].encode('utf-8')
        newname = request.form['ip'].encode('utf-8')
        legal = check_ip(newname)
        if legal == 0:
            return "-3"
        else:
            machine = Cipermachine.query.filter_by(id=id).first()
            if oldname.find('DMS') != -1:
                if oldname.find('ecc') != -1:
                    newname = 'DMS_ecc_' + newname
                else:
                    newname = 'DMS_' + newname
                renamecert = privatecert.CRenameManagementCert(id, machine.ip, [oldname,  newname])
            else:
                if oldname.find('ecc') != -1:
                    newname = 'ecc_' + newname
                renamecert = privatecert.RenameCert(id, machine.ip, [oldname, newname],machine.encrypttype)
            status = renamecert.SendAndReceive()
            return str(status)

    @app.route('/privateequipment/serachcert/<int:id>',methods=['POST'])
    def private_search_cert(id):
        ip = request.form['sip']
        finalresult = DPrivateCertInfo.query.filter(DPrivateCertInfo.cert_name.like('%' + ip  + '%')).filter_by(id=id).all()
        machine = Cipermachine.query.filter_by(id=id).first()
        return render_template('privatecertmanage2.html',machine=machine,certificates=finalresult)




## 3、隧道管理
    @app.route('/privateequipment/privatechannel/<int:id>', methods=['GET'])
    def private_channel(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            mainmode = False
            machine = Cipermachine.query.filter_by(id=id).first()
            querysystemconfigure = privatesystem.CQuerySystemInfo(id,machine.ip,[0],machine.encrypttype)
            status = querysystemconfigure.SendAndReceive()
            if status == 0:
                equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
                if equipmentstatus != None and equipmentstatus.master_master_channel != None:
                    mainmode = equipmentstatus.master_master_channel
            querycertlist = privatecert.CQueryCertList(id,machine.ip,machine.encrypttype)
            status2 = querycertlist.SendAndReceive()
            certificate = models.DPrivateCertInfo.query.filter_by(id=id, cert_type=5).all()
            vlan = models.DVlanList.query.filter_by(id=id,lino=0).order_by(models.DVlanList.vid.asc()).all()
            machine = Cipermachine.query.filter_by(id=id).first()
            linkinfo = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=1).first()
            if linkinfo != None:
                line = linkinfo.line_work_enable
            else:
                line = False
            channels = models.DPrivateChannelInfo.query.filter_by(id=id,lino=0).order_by(models.DPrivateChannelInfo.channelnumber).all()
            flag = False
            for channel in channels:
                if channel.vlan_id == None:
                    querychannel = privatechannel.CQueryChannel(id,machine.ip,machine.encrypttype)
                    status = querychannel.SendAndReceive()
                    if status == 0:
                        flag = True
            if flag:
                channels = models.DPrivateChannelInfo.query.filter_by(id=id,lino=0).order_by(models.DPrivateChannelInfo.channelnumber).all()
            channel_total = len(channels)
            return render_template('privatechannel.html',machine=machine,channels=channels,mainmode=mainmode,certificates=certificate,vlans=vlan,line=line,channel_total=channel_total)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatechannel2/<int:id>', methods=['GET'])
    def private_channel2(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            mainmode = False
            machine = Cipermachine.query.filter_by(id=id).first()
            querysystemconfigure = privatesystem.CQuerySystemInfo(id,machine.ip,[1],machine.encrypttype)
            status = querysystemconfigure.SendAndReceive()
            if status == 0:
                equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
                if equipmentstatus != None and equipmentstatus.master_master_channel != None:
                    mainmode = equipmentstatus.master_master_channel         
            certificate = models.DPrivateCertInfo.query.filter_by(id=id, cert_type=5).all()
            vlan = models.DVlanList.query.filter_by(id=id,lino=1).order_by(models.DVlanList.vid.asc()).all()
            machine = Cipermachine.query.filter_by(id=id).first()
            channels = models.DPrivateChannelInfo.query.filter_by(id=id,lino=1).order_by(models.DPrivateChannelInfo.channelnumber).all()
            flag = False
            for channel in channels:
                if channel.vlan_id == None:
                    querychannel = privatechannel.CQueryChannel(id,machine.ip,machine.encrypttype)
                    status = querychannel.SendAndReceive()
                    if status == 0:
                        flag = True
            if flag:
                channels = models.DPrivateChannelInfo.query.filter_by(id=id,lino=0).order_by(models.DPrivateChannelInfo.channelnumber).all()
            channel_total = len(channels)            
            return render_template('privatechannel2.html',machine=machine,channels=channels,mainmode=mainmode,certificates=certificate,vlans=vlan)
        else:
            return redirect('/')

    @app.route('/privateequipment/setmainmode/<int:id>',methods=['POST'])
    def pivate_set_main_mode(id):
        whether = int(request.form['whether'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setmastermaster = privatechannel.SetMasterMasterChannel(id, machine.ip, [whether],machine.encrypttype)
        status = setmastermaster.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/findchannel/<int:id>',methods=['POST'])
    def private_query_channel(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        querychannel = privatechannel.CQueryChannel(id,machine.ip,machine.encrypttype)
        status = querychannel.SendAndReceive()
        return str(status)
        #return "0"

    @app.route('/privateequipment/addchannel/<int:id>',methods=['POST'])
    def private_add_channel(id):
        relacert = int(request.form['relacert'])
        ip_cert = request.form['certificateid'].encode('utf-8')
        ip_peer = (request.form['ip']).encode('utf-8')
        workmodel = int(request.form['cworkmodel'])
        vid = request.form['vlan']
        if request.form['vlan'] == "":
            vid = 0
        else:
            vid = int(request.form['vlan'])
        chname = request.form['channelname'].decode('utf-8').encode('gbk')
        teamid = 0
        linenumber = int(request.form['lino'])
        if relacert == 1:
            ipaddr = ip_cert
            if ipaddr == "":
                return "-8"
            else:
                record = models.DPrivateChannelInfo.query.filter_by(id=id, peer_addr=ipaddr,lino=linenumber).first()
                if record != None:
                    return "-7"
        else:
            ipaddr = ip_peer
            legal = check_ip(ipaddr)
            if legal == 0:
                return "-6"
        machine = Cipermachine.query.filter_by(id=id).first()
        parameters = [ipaddr, workmodel, vid, chname, teamid, linenumber]
        addchannel = privatechannel.CAddChannel(id, machine.ip, parameters,machine.encrypttype)
        status = addchannel.SendAndReceive()
        if status == 0:
            querychannel = privatechannel.CQueryChannel(id,machine.ip,machine.encrypttype)
            querychannel.SendAndReceive()
        return str(status)


    @app.route('/privateequipment/deletechannel/<int:id>',methods=['POST'])
    def private_delete_channel(id):
        channelnumbers = request.form['choosechannelnumber'].encode('utf-8').strip(',').split(',')
        #print "########",channelnumbers
        #return str(0)
        result = 0
        for channelnumber in channelnumbers:
             machine = Cipermachine.query.filter_by(id=id).first()
             deletechannel = privatechannel.CDeleteChannel(id, machine.ip, [int(channelnumber)],machine.encrypttype)
             status = deletechannel.SendAndReceive()
             if(status != 0):
                result = status
             if(status == -2):
                return str(status)
        return str(result)

    @app.route('/privateequipment/editchannelname/<int:id>',methods=['POST'])
    def edit_channel_name(id):
        newname = request.form['newname'].decode('utf-8').encode('gbk')
        channelnumber = int(request.form['choosechannelnumber'])
        machine = Cipermachine.query.filter_by(id=id).first()
        renamechannel = privatechannel.CRenameChannel(id, machine.ip, [channelnumber, newname],machine.encrypttype)
        status = renamechannel.SendAndReceive()
        return str(status)
 
    @app.route('/privateequipment/probechannel/<int:id>',methods=['POST'])
    def private_probe_channel(id):
        channelnumber = int(request.form['choosechannelnumber'])
        machine = Cipermachine.query.filter_by(id=id).first()
        senddetectrequest = privatechannel.CSendDetectRequest(id, machine.ip, [channelnumber],machine.encrypttype)
        status = senddetectrequest.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/bindchannel/<int:id>',methods=['POST']) 
    def private_bind_channel(id):
        channelnumber = request.form['choosechannelnumber'].split(',')
        channel1 = int(channelnumber[0])
        channel2 = int(channelnumber[1])
        channels = models.DPrivateChannelInfo.query.filter_by(id=id)
        channel1_info = channels.filter_by(channelnumber=channel1).first()
        channel2_info = channels.filter_by(channelnumber=channel2).first()
        if channel1_info.channelnumber_band != 0 or channel2_info.channelnumber_band != 0:
            return '-4'
        machine = Cipermachine.query.filter_by(id=id).first()
        bindchannel = privatechannel.CBindChannel(id, machine.ip, [channel1, channel2],machine.encrypttype)
        status = bindchannel.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/unbindchannel/<int:id>',methods=['POST']) 
    def private_unbind_channel(id):
        channelnumber = request.form['choosechannelnumber'].split(',')
        channel1 = int(channelnumber[0])
        channel2 = int(channelnumber[1])
        channels = models.DPrivateChannelInfo.query.filter_by(id=id)
        channel1_info = channels.filter_by(channelnumber=channel1).first()
        channel2_info = channels.filter_by(channelnumber=channel2).first()
        if channel1_info.channelnumber_band != channel2 or channel2_info.channelnumber_band != channel1:
            return '-5'        
        machine = Cipermachine.query.filter_by(id=id).first()
        relievebandchannel = privatechannel.CRelieveBandChannel(id, machine.ip, [channel1,channel2],machine.encrypttype)
        status = relievebandchannel.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/setchannelgroup/<int:id>',methods=['POST'])
    def private_set_channel_group(id):
        totalchoosenumber = int(request.form['totalchoosenumber'])
        channelnumbers= request.form['choosechannelnumber'].encode('utf-8').strip(',').split(',')

        group = int(request.form['group'])  
        if group == 0:
            channelinfos = models.DPrivateChannelInfo.query.filter_by(id=id).all()
            teamids = []
            for channelinfo in channelinfos:
                teamids.append(channelinfo.teamid)
            templen = len(teamids)
            teamid = 1
            for teamid in range(1,templen + 2):
                if teamid not in teamids:
                    break
        elif group == 1:
            teamid = int(request.form['groupnumber'])
        else :
            teamid = 0

        parameters = [totalchoosenumber, teamid]
        for channelnumber in channelnumbers:
            parameters.append(int(channelnumber))
        machine = Cipermachine.query.filter_by(id=id).first()
        bindchannelteam = privatechannel.CBindChannelTeam(id, machine.ip, parameters,machine.encrypttype)
        status = bindchannelteam.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/resetchannel/<int:id>',methods=['POST'])
    def private_reset_channel(id):
        channelnumber = request.form['choosechannelnumber']
        machine = Cipermachine.query.filter_by(id = id).first()
        ip = machine.ip.encode('utf-8')
        parameter = [int(channelnumber.encode('utf-8'))]
        resetchannel = privatechannel.CResetChannel(id, ip, parameter,machine.encrypttype)
        status = resetchannel.SendAndReceive()
        return str(status)

## 4、策略管理
    @app.route('/privateequipment/privatestrategy/<int:id>/<int:number>', methods=['GET'])
    def private_strategy(id,number):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            machine = Cipermachine.query.filter_by(id=id).first()
            peer_ip = db.session.query(models.DPrivateChannelInfo.peer_addr).filter_by(id=id,channelnumber=number).first()
            channels = db.session.query(models.DPrivateChannelInfo.id, models.DPrivateChannelInfo.lino, models.DPrivateChannelInfo.channelnumber, models.DPrivateChannelInfo.channelname).filter_by(id=id).all()   
            page = request.args.get("page",1,type=int)
            per_pagecount = 8
            querystrategylist = privatestrategy.CQueryStrategyList(id, machine.ip, [number],machine.encrypttype)            
            status,stragetynums,strategies = querystrategylist.SendAndReceive()
            # status = 0.
            # stragetynums = 10
            if status == 0:
                strategyquery = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number)
                pagination = strategyquery.paginate(page, per_page = per_pagecount, error_out = False)
                strategies = pagination.items
                # strategies = strategyquery.all()
                strategiescount = strategyquery.count()
                if stragetynums != strategiescount:
                    for strategy in strategies:
                        db.session.delete(strategy)
                    db.session.commit()
                    for index in range(stragetynums):
                        strategy = models.DPrivateSecurityStrategy(id,number,index)
                        db.session.add(strategy)
                    db.session.commit()
            pagination = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).paginate(page, per_page=per_pagecount, error_out=False)
            strategies = pagination.items            
            # strategies = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).all()
            records = []
            for index,strategy in enumerate(strategies):
                if strategy.Policy_Name == "未知":
                    querystrategycontent = privatestrategy.CQueryPolicy(id,machine.ip,[number,index],machine.encrypttype)
                    status, record = querystrategycontent.SendAndReceive()
                    if status == -2:
                        break
                    if status == 0:
                        records.append(record)
            if len(records) != 0:
                db.session.add_all(records)
                db.session.commit()
                pagination = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).paginate(page, per_page=per_pagecount, error_out=False)
                strategies = pagination.items                
                # strategies = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).all()              
            return render_template('privatestrategy.html',machine=machine, channels=channels,pagination=pagination,strategies=strategies,channel_number=number,sport1 = 0,sport2=65535,dport1=0,dport2=65535,peer_addr=peer_ip.peer_addr,limit=0)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatestrategy/pagination', methods=['GET'])
    def private_strategy_pagination():
        id = request.args.get('machineid',1,type=int)
        number = request.args.get('cid',1,type=int)
        page = request.args.get('page',1,type=int)
        machine = Cipermachine.query.filter_by(id=id).first()        
        peer_ip = db.session.query(models.DPrivateChannelInfo.peer_addr).filter_by(id=id,channelnumber=number).first()
        per_pagecount = 8
        pagination = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).paginate(page, per_page=per_pagecount, error_out=False)
        strategies = pagination.items
        records = []        
        for index,strategy in enumerate(strategies):
            if strategy.Policy_Name == "未知":
                querystrategycontent = privatestrategy.CQueryPolicy(id,machine.ip,[number,index + (page - 1) * per_pagecount],machine.encrypttype)
                status, record = querystrategycontent.SendAndReceive()
                if status == -2:
                    break
                if status == 0:
                    records.append(record)
        if len(records) != 0:
            db.session.add_all(records)
            db.session.commit()
        pagination = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).paginate(page, per_page=per_pagecount, error_out=False)
        strategies = pagination.items
        channels = db.session.query(models.DPrivateChannelInfo.id, models.DPrivateChannelInfo.lino, models.DPrivateChannelInfo.channelnumber,models.DPrivateChannelInfo.channelname).filter_by(id=id).all()
        return render_template('privatestrategy.html',machine=machine, channels=channels,strategies=strategies,pagination=pagination,channel_number=number,sport1 = 0,sport2=65535,dport1=0,dport2=65535,peer_addr=peer_ip.peer_addr,limit=0)        

    @app.route('/privateequipment/querychannelstrategy/<int:id>/<int:number>',methods=['GET'])
    def private_query_strategy(id,number):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            page = request.args.get('page',1,type=int)
            per_pagecount = 8
            peer_ip = db.session.query(models.DPrivateChannelInfo.peer_addr).filter_by(id=id,channelnumber=number).first()
            channels = db.session.query(models.DPrivateChannelInfo.id, models.DPrivateChannelInfo.lino, models.DPrivateChannelInfo.channelnumber, models.DPrivateChannelInfo.channelname).filter_by(id=id).all()   
            strategies = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).all()
            for strategy in strategies:
                db.session.delete(strategy)
            db.session.commit()
            machine = Cipermachine.query.filter_by(id=id).first()
            querystrategylist = privatestrategy.CQueryStrategyList(id, machine.ip, [number], machine.encrypttype)            
            status,stragetynums,strategies = querystrategylist.SendAndReceive()
            if status == 0:
                for index in range(stragetynums):
                    strategy = models.DPrivateSecurityStrategy(id,number,index)
                    db.session.add(strategy)
                db.session.commit()
            strategyquery = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number)
            pagination = strategyquery.paginate(page, per_page = per_pagecount, error_out=False)
            strategies = pagination.items
            records = []
            for index,strategy in enumerate(strategies):
                if strategy.Policy_Name == "未知":
                    querystrategycontent = privatestrategy.CQueryPolicy(id, machine.ip, [number,index] ,machine.encrypttype)
                    status, record = querystrategycontent.SendAndReceive()
                    if status == -2:
                        break
                    if status == 0:
                        records.append(record)
            if len(records) != 0:
                db.session.add_all(records)
                db.session.commit()
            strategyquery = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number)
            pagination = strategyquery.paginate(page, per_page = per_pagecount, error_out=False)
            strategies = pagination.items
            return render_template ('privatestrategy.html',machine=machine,pagination=pagination,channels=channels,strategies=strategies,channel_number=number, peer_addr=peer_ip.peer_addr,sport1 = 0,sport2=65535,dport1=0,dport2=65535,limit=0)
        else:
            return redirect('/')        

    @app.route('/privateequipment/addchannelstrategy/<int:id>/<int:number>',methods=['POST'])
    def private_add_strategy(id,number):
        sip = request.form['sip'].encode('utf-8')
        dip = request.form['dip'].encode('utf-8')
        tip = request.form['tip'].encode('utf-8')
        tdip = request.form['tdip'].encode('utf-8')

        sport1 = int(request.form['sport1'])
        sport2 = int(request.form['sport2'])
        dport1 = int(request.form['dport1'])
        dport2 = int(request.form['dport2'])

        limit = int(request.form['limit'])

        legal1 = check_ip(sip)
        legal2 = check_ip(dip)
        legal3 = check_ip(tip)
        legal4 = check_ip(tdip)
        if legal1 & legal2 & legal3 &legal4 == 0:
            return "-4"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(sip))[0]
            ip2 = struct.unpack('!L',socket.inet_aton(dip))[0]
            ip3 = struct.unpack('!L',socket.inet_aton(tip))[0]
            ip4 = struct.unpack('!L',socket.inet_aton(tdip))[0]
            com1 = ip1 - ip2
            com2 = ip3 - ip4
            pare1 = sport1 - sport2
            pare2 = dport1 - dport2
            if com1 > 0 or com2 >0 or pare1>0 or pare2>0 or sport2 > 65535 or dport2 > 65535 or limit <0 or limit >100:
                return "-3"
            else:
                destination = int(request.form['destination'])
                protocol = int(request.form['protocol'])
                workmodel = int(request.form['workmodel'])
                nat = int(request.form['nat'])
                name = request.form['name'].decode('utf-8').encode('gbk')
                name1 = request.form['name']
                priority = int(request.form['priority'])
                parameters = [number, sip, dip,tip,tdip, sport1, sport2, dport1, dport2, destination, protocol, workmodel, nat, name, limit, priority]
                machine = Cipermachine.query.filter_by(id=id).first()
                addchannelstrategy = privatestrategy.CAddStrategy(id, machine.ip, parameters,machine.encrypttype)
                status = addchannelstrategy.SendAndReceive()
                if status == 0:
                    count = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).count()
                    newrecord = models.DPrivateSecurityStrategy(id,number,count, sip,dip,tip,tdip,sport1,sport2,dport1,dport2,destination,protocol,workmodel,nat, name1, limit, priority)
                    db.session.add(newrecord)
                    db.session.commit()
                print status
                return str(status)

    @app.route('/privateequipment/querystrategycontent/<int:id>/<int:number>',methods=['POST'])
    def private_query_strategy_content(id,number):
        print #########################################
        cstragetynum = int(request.form['cstragetynum'])
        machine = Cipermachine.query.filter_by(id=id).first()
        querystrategycontent = privatestrategy.CQueryPolicy(id,machine.ip,[number,cstragetynum],machine.encrypttype)
        status, record = querystrategycontent.SendAndReceive()
        if status != 0:
            return jsonify({"status":str(status)})
        # else:
        #     if record.Policy_Name == "未知":
        #         querystrategycontent = privatestrategy.CQueryPolicy(id,machine.ip,[number,cstragetynum],machine.encrypttype)
        #         status, record = querystrategycontent.SendAndReceive()
        #     if status != 0:
        #         return jsonify({"status":str(status)})  
                  
        strategy = models.DPrivateSecurityStrategy.query.filter_by(id=id, channelnumber=number).all()[cstragetynum]
        strategy.strategynumber = cstragetynum
        strategy.Source_Begin_IP = record.Source_Begin_IP
        strategy.Source_End_IP = record.Source_End_IP
        strategy.Dest_Begin_IP = record.Dest_Begin_IP
        strategy.Dest_End_IP = record.Dest_End_IP
        strategy.Port_Source_Begin = record.Port_Source_Begin
        strategy.Port_Source_End = record.Port_Source_End
        strategy.Port_Dest_Begin = record.Port_Dest_Begin
        strategy.Port_Dest_End = record.Port_Dest_End
        strategy.Direction = record.Direction
        strategy.Protocol = record.Protocol
        strategy.WorkMode = record.WorkMode
        strategy.NatMode = record.NatMode
        strategy.Policy_Name = record.Policy_Name
        strategy.Policy_limit = record.Policy_limit
        strategy.Policy_level = record.Policy_level
        db.session.add(strategy)           
        db.session.commit()


        data = {"status":str(status),"Source_Begin_IP":strategy.Source_Begin_IP,"Source_End_IP":strategy.Source_End_IP,\
        "Dest_Begin_IP":strategy.Dest_Begin_IP,"Dest_End_IP":strategy.Dest_End_IP,"Port_Source_Begin":strategy.Port_Source_Begin,\
        'Port_Source_End':strategy.Port_Source_End,"Port_Dest_Begin":strategy.Port_Dest_Begin,"Port_Dest_End":strategy.Port_Dest_End,\
        "Direction":strategy.Direction,"Protocol":strategy.Protocol,"WorkMode":strategy.WorkMode,"NatMode":strategy.NatMode,\
        "Policy_Name":strategy.Policy_Name, "Policy_limit":strategy.Policy_limit, "Policy_level":strategy.Policy_level}
        return jsonify(data)
        
    @app.route('/privateequipment/editstrategy/<int:id>/<int:number>',methods=['POST'])
    def private_edit_strategy(id,number):
        cstrnumber = int(request.form['cstrnumber'])
        print "#########  cstrnumber = ",cstrnumber
        sip = request.form['sip'].encode('utf-8')
        dip = request.form['dip'].encode('utf-8')
        tip = request.form['tip'].encode('utf-8')
        tdip = request.form['tdip'].encode('utf-8')

        sport1 = int(request.form['sport1'])
        sport2 = int(request.form['sport2'])
        dport1 = int(request.form['dport1'])
        dport2 = int(request.form['dport2'])

        limit = int(request.form['limit'])

        legal1 = check_ip(sip)
        legal2 = check_ip(dip)
        legal3 = check_ip(tip)
        legal4 = check_ip(tdip)
        if legal1 & legal2 & legal3 &legal4 == 0:
            return "-4"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(sip))[0]
            ip2 = struct.unpack('!L',socket.inet_aton(dip))[0]
            ip3 = struct.unpack('!L',socket.inet_aton(tip))[0]
            ip4 = struct.unpack('!L',socket.inet_aton(tdip))[0]
            com1 = ip1 - ip2
            com2 = ip3 - ip4
            pare1 = sport1 - sport2
            pare2 = dport1 - dport2
            if com1 > 0 or com2 >0 or pare1>0 or pare2>0 or sport2 > 65535 or dport2 > 65535 or limit <0 or limit >100:
                return "-3"
            else: 
                destination = int(request.form['destination'])
                protocol = int(request.form['protocol'])
                workmodel = int(request.form['workmodel'])
                nat = int(request.form['nat'])
                name = request.form['name'].decode('utf-8').encode('gbk')
                name1 = request.form['name'].encode('utf-8')
                priority = int(request.form['priority'])
                parameters = [number, sip, dip,tip,tdip, sport1, sport2, dport1, dport2, destination, protocol, workmodel, nat, name, limit, priority]
                machine = Cipermachine.query.filter_by(id=id).first()
                ## 先删除这条通道
                deletestrategy = privatestrategy.CDeleteSecurityStrategy(id, machine.ip, [number, cstrnumber],machine.encrypttype)
                status = deletestrategy.SendAndReceive()
                #return "0"
                if status == 0:
                    ##删除成功了，从数据库中删除这条策略
                    strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()
                    db.session.delete(strategys[cstrnumber])
                    db.session.commit()
                    ###
                    addstrategy = privatestrategy.CAddStrategy(id, machine.ip, parameters,machine.encrypttype)
                    status2 = addstrategy.SendAndReceive()
                    if status2 == 0:
                        ##添加成功，添加到数据库中
                        ##新增的策略在最后一条
                        print "修改成功"
                        newrecord = models.DPrivateSecurityStrategy(id,number,len(strategys) - 1, sip,dip,tip,tdip,sport1,sport2,dport1,dport2,destination,protocol,workmodel,nat, name1, limit, priority)
                        db.session.add(newrecord)
                        db.session.commit()
                        ####
                        return str(status2)
                    else:
                        ###添加失败了，复原
                        #strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()
                        stragety = strategys[cstrnumber]
                        channelnumber = stragety.channelnumber

                        Source_Begin_IP = stragety.Source_Begin_IP.encode('utf-8')
                        Source_End_IP = stragety.Source_End_IP.encode('utf-8')
                        Dest_Begin_IP = stragety.Dest_Begin_IP.encode('utf-8')
                        Dest_End_IP = stragety.Dest_End_IP.encode('utf-8')

                        #print Source_Begin_IP,Source_End_IP,Dest_Begin_IP,Dest_End_IP

                        Port_Source_Begin = stragety.Port_Source_Begin
                        Port_Source_End = stragety.Port_Source_End
                        Port_Dest_Begin = stragety.Port_Dest_Begin
                        Port_Dest_End = stragety.Port_Dest_End

                        Direction = stragety.Direction
                        Protocol = stragety.Protocol
                        NatMode = stragety.NatMode

                        Policy_Name = stragety.Policy_Name.encode('utf-8')
                        Policy_limit = stragety.Policy_limit
                        Policy_level = stragety.Policy_level
                        
                        OldWorkMode = stragety.WorkMode                    
                    
                        parameters = [channelnumber, Source_Begin_IP,Source_End_IP, Dest_Begin_IP,\
                                    Dest_End_IP, Port_Source_Begin, Port_Source_End, Port_Dest_Begin, Port_Dest_End,\
                                    Direction, Protocol, OldWorkMode, NatMode,  Policy_Name, Policy_limit, Policy_level]
                        addstrategy = privatestrategy.CAddStrategy(id,machine.ip, parameters,machine.encrypttype)
                        status3 = addstrategy.SendAndReceive()
                        if status3 == 0:
                            ##复原成功了
                            #strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()
                            #db.session.delete(strategys[cstrnumber])
                            #db.session.commit()
                            #db.session.close()
                            ##
                            ###添加到最后一条
                            newrecord = models.DPrivateSecurityStrategy(id,channelnumber,len(strategys) - 1, Source_Begin_IP,Source_End_IP,Dest_Begin_IP,Dest_End_IP,\
                                Port_Source_Begin,Port_Source_End,Port_Dest_Begin,Port_Dest_End,\
                                Direction,Protocol,OldWorkMode,NatMode, Policy_Name, Policy_limit, Policy_level)
                            db.session.add(newrecord)
                            db.session.commit()                            
                            return "-6"
                        else:
                            return "-7"
                return str(status)

    @app.route('/privateequipment/batcheditstrategy/<int:id>/<int:number>',methods=['POST'])
    def private_edit_batch_strategy(id,number):
        strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()
        machine = Cipermachine.query.filter_by(id=id).first()
        workmode = int(request.form['workmode'])
        alert = ""
        status = 0
        
        ## 查看是否有没有查询内容的策略####
        record = []
        for index,strategy in enumerate(strategys):
            if strategy.Policy_Name == "未知":
                querystrategycontent = privatestrategy.CQueryPolicy(id,machine.ip,[number,index],machine.encrypttype)
                status, record = querystrategycontent.SendAndReceive()
                if status == -2:
                    return jsonify({"status":str(status),"AlertInfo":SwitchErrorCode(status)}) 
                if status == 0:
                    records.append(record)
                    if len(records) != 0:
                        db.session.add_all(records)
                        db.session.commit()
                        strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()
        deleterecords = []     
        addrecords = []        
        for stragetynum,stragety in enumerate(strategys):
            if stragety.Policy_Name == "未知":##应该不会出现这种情况
                break
            deletestrategy = privatestrategy.CDeleteSecurityStrategy(id, machine.ip, [number, 0],machine.encrypttype)
            status = deletestrategy.SendAndReceive()
            if status != 0: 
                alert = alert + '策略 ' + stragety.Policy_Name + ' 修改失败批量修改中止！错误原因：' + SwitchErrorCode(status) + '\n'
                ## 只要有一个失败了，立刻结束
                break
                # if status == -2:
                #     break
                # else:
                #     continue
            ##删除成功后，把要删除的策略放到列表中，最后一次性删除
            deleterecords.append(stragety)

            ## 添加通道
            channelnumber = stragety.channelnumber
            Source_Begin_IP = stragety.Source_Begin_IP.encode('utf-8')
            Source_End_IP = stragety.Source_End_IP.encode('utf-8')
            Dest_Begin_IP = stragety.Dest_Begin_IP.encode('utf-8')
            Dest_End_IP = stragety.Dest_End_IP.encode('utf-8')

            Port_Source_Begin = stragety.Port_Source_Begin
            Port_Source_End = stragety.Port_Source_End
            Port_Dest_Begin = stragety.Port_Dest_Begin
            Port_Dest_End = stragety.Port_Dest_End

            Direction = stragety.Direction
            Protocol = stragety.Protocol
            NatMode = stragety.NatMode

            Policy_Name = stragety.Policy_Name.encode('gbk')
            Policy_limit = stragety.Policy_limit
            Policy_level = stragety.Policy_level
            
            OldWorkMode = strategy.WorkMode

            parameters = [channelnumber, Source_Begin_IP,Source_End_IP, Dest_Begin_IP,\
            Dest_End_IP, Port_Source_Begin, Port_Source_End, Port_Dest_Begin, Port_Dest_End,\
            Direction, Protocol, workmode, NatMode,  Policy_Name, Policy_limit, Policy_level]
            addstrategy = privatestrategy.CAddStrategy(id,machine.ip, parameters,machine.encrypttype)
            status = addstrategy.SendAndReceive()

            if status != 0: ##添加失败了
                #db.session.delete(stragety)
                #alert = alert + '策略' + str(stragetynum) + '修改失败，错误原因：' + SwitchErrorCode(status) + '\n'
                
                ### 恢复

                #for i in range(1,len(strategys)):
                #    restrategy = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number,strategynumber=(stragetynum-1)).first()
                reparameters = [channelnumber, Source_Begin_IP,Source_End_IP, Dest_Begin_IP,\
                Dest_End_IP, Port_Source_Begin, Port_Source_End, Port_Dest_Begin, Port_Dest_End,\
                Direction, Protocol, OldWorkMode, NatMode,  Policy_Name, Policy_limit, Policy_level]
                addstrategy = privatestrategy.CAddStrategy(id,machine.ip, reparameters,machine.encrypttype)
                status2 = addstrategy.SendAndReceive()                    
                if status2 == 0: ##恢复成功
                    newrecord = models.DPrivateSecurityStrategy(id,channelnumber,len(strategys) - 1, Source_Begin_IP,Source_End_IP,Dest_Begin_IP,Dest_End_IP,\
                                Port_Source_Begin,Port_Source_End,Port_Dest_Begin,Port_Dest_End,\
                                Direction,Protocol,OldWorkMode,NatMode, Policy_Name, Policy_limit, Policy_level)
                    addrecords.append(newrecord)                
                    alert = alert + '策略 ' + stragety.Policy_Name + ' 修改失败，已恢复！错误原因：' + SwitchErrorCode(status) + '\n'
                else:
                    alert = alert + '策略 ' + stragety.Policy_Name + ' 修改失败，恢复时出错，策略丢失！错误原因：' + SwitchErrorCode(status2) + '\n'
                    #if status2 == -2:
                        
                        
                # if restrategy != None:
                #     parameters = [channelnumber, str(restrategy.Source_Begin_IP),str(restrategy.Source_End_IP), str(restrategy.Dest_Begin_IP),\
                #             str(restrategy.Dest_End_IP), (restrategy.Port_Source_Begin), (restrategy.Port_Source_End), (restrategy.Port_Dest_Begin), (restrategy.Port_Dest_End),\
                #             (restrategy.Direction), (restrategy.Protocol), (restrategy.WorkMode), int(restrategy.NatMode),  str(restrategy.Policy_Name), (restrategy.Policy_limit), (restrategy.Policy_level)]
                #     print parameters
                # addstrategy = privatestrategy.CAddStrategy(id,machine.ip, parameters,machine.encrypttype)
                # status2 = addstrategy.SendAndReceive()
                # if status2 != 0:
                #     alert = alert + '策略' + str(stragetynum) + '恢复失败，错误原因：' + SwitchErrorCode(status2) + '\n'                 
                # if status == -2:
                #     break
                # else:
                #     continue
            else:##添加成功
                newrecord = models.DPrivateSecurityStrategy(id,channelnumber,len(strategys) - 1, Source_Begin_IP,Source_End_IP,Dest_Begin_IP,Dest_End_IP,\
                                Port_Source_Begin,Port_Source_End,Port_Dest_Begin,Port_Dest_End,\
                                Direction,Protocol,workmode,NatMode, Policy_Name, Policy_limit, Policy_level)
                addrecords.append(newrecord)
        for deleterecord in deleterecords:
            db.session.delete(deleterecord)
        db.session.add_all(addrecords)

                #stragety.WorkMode = workmode
                #db.session.add(stragety)
        db.session.commit()
        if len(alert) == 0:##没有错误
            status = 0
        else:
            status = 1
        return jsonify({"status":str(status),"AlertInfo":alert})


    @app.route('/privateequipment/deletechannelstrategy/<int:id>/<int:number>',methods=['POST'])
    def private_delete_strategy(id,number):

        cstragetynum = int(request.form['cstrnumber'])
        print "@@@@@@@@@@deletestrategy@@@@@@@@@ ",cstragetynum
        machine = Cipermachine.query.filter_by(id=id).first()        
        deletestrategy = privatestrategy.CDeleteSecurityStrategy(id, machine.ip, [number,cstragetynum],machine.encrypttype)
        status = deletestrategy.SendAndReceive()
        if status == 0:
            strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()
            db.session.delete(strategys[cstragetynum])
            db.session.commit()
        return str(status)

    @app.route('/privateequipment/batchdeletestrategy/<int:id>/<int:number>',methods=['POST'])
    def private_delete_batch_strategy(id,number):
        machine = Cipermachine.query.filter_by(id=id).first()
        strategys = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).all()        
        alert=''
        status = 0   
        for stragetynum,strategy in enumerate(strategys):
            deletestrategy = privatestrategy.CDeleteSecurityStrategy(id, machine.ip, [number,0],machine.encrypttype)
            status = deletestrategy.SendAndReceive()
            if status != 0:
                alert = alert + '策略 ' + strategy.Policy_Name + ' 删除失败, 批量删除中止！错误原因：' + SwitchErrorCode(status) + '\n'
                break
            db.session.delete(strategy)
        db.session.commit()
        return jsonify({"status":str(status),"AlertInfo":alert})


    @app.route('/privateequipment/copychannelstrategy/<int:id>',methods=['POST'])
    def private_strategy_copy(id):
        number = int(request.form['choosechannelnumber'])
        if number == "":
            return "-5"
        else:
            sip = request.form['sip'].encode('utf-8')
            dip = request.form['dip'].encode('utf-8')
            tip = request.form['tip'].encode('utf-8')
            tdip = request.form['tdip'].encode('utf-8')

            sport1 = int(request.form['sport1'])
            sport2 = int(request.form['sport2'])
            dport1 = int(request.form['dport1'])
            dport2 = int(request.form['dport2']) 

            legal1 = check_ip(sip)
            legal2 = check_ip(dip)
            legal3 = check_ip(tip)
            legal4 = check_ip(tdip)
            if legal1 & legal2 & legal3 &legal4 == 0:
                return "-4"
            else:
                ip1 = struct.unpack('!L',socket.inet_aton(sip))[0]
                ip2 = struct.unpack('!L',socket.inet_aton(dip))[0]
                ip3 = struct.unpack('!L',socket.inet_aton(tip))[0]
                ip4 = struct.unpack('!L',socket.inet_aton(tdip))[0]
                com1 = ip1 - ip2
                com2 = ip3 - ip4
                pare1 = sport1 - sport2
                pare2 = dport1 - dport2
                if com1 > 0 or com2 >0 or pare1>0 or pare2>0 or sport2 > 65535 or dport2 > 65535:
                    return "-3"
                else:
                    destination = int(request.form['destination'])
                    protocol = int(request.form['protocol'])
                    workmodel = int(request.form['workmodel'])
                    nat = int(request.form['nat'])
                    name = request.form['name'].decode('utf-8').encode('gbk')
                    name1 = request.form['name'].encode('utf-8')
                    li = request.form['limit']
                    if li == "":
                        limit = 0
                    else:
                        limit = int(request.form['limit'])
                    priority = int(request.form['priority'])
                    parameters = [number, sip, dip,tip,tdip, sport1, sport2, dport1, dport2, destination, protocol, workmodel, nat, name, limit, priority]
                    machine = Cipermachine.query.filter_by(id=id).first()
                    addchannelstrategy = privatestrategy.CAddStrategy(id, machine.ip, parameters,machine.encrypttype)
                    status = addchannelstrategy.SendAndReceive()
                    if status == 0:
                        count = models.DPrivateSecurityStrategy.query.filter_by(id=id,channelnumber=number).count()
                        newrecord = models.DPrivateSecurityStrategy(id,number,count, sip,dip,tip,tdip,sport1,sport2,dport1,dport2,destination,protocol,workmodel,nat, name1, limit, priority)
                        db.session.add(newrecord)
                        db.session.commit()
                    return str(status)

## 5、系统管理

##  1)、网络配置
    @app.route('/privateequipment/privatesystem/net/<int:id>', methods=['GET'])
    def private_net(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            machine = Cipermachine.query.filter_by(id=id).first()
            line = False
            natip = False
            vip = False
            tree = False
            tranmission = True
            admission = False
            fragment = False
            ipaddr = ''
            ipmask = ''
            natipaddr = ''
            natipmask = ''
            
            querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0],machine.encrypttype)
            status1 =  querysystemconfigure.SendAndReceive()
            getnatconfig = privatenetwork.CGetNatConfig(id, machine.ip,[0],machine.encrypttype)
            status2 = getnatconfig.SendAndReceive() 
            getallowedaccessstate = privatenetwork.CGetAllowedAccessState(id,machine.ip,machine.encrypttype)
            status3 = getallowedaccessstate.SendAndReceive()               
            if status1 == 0 or status2 == 0 or status3 == 0 :
                linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=0).first()
                if status1 == 0:
                    line = linkstatus.line_work_enable
                    tree = linkstatus.stp_state
                    tranmission = linkstatus.global_forward_policy
                    vip = linkstatus.virtual_ip_enabled
                    fragment = linkstatus.post_fragment_enabled
                    ipaddr = linkstatus.ipaddr
                    ipmask = linkstatus.ipmask
                if status2 == 0:   
                    natip = linkstatus.nat_ip_enabled                        
                    natipaddr = linkstatus.nat_ipaddr
                    natipmask = linkstatus.nat_ipmask
                if status3 == 0:
                    admission = linkstatus.is_allowed_access

                for eachone in [line, tree, tranmission, vip, fragment, ipaddr, ipmask]:
                    if eachone == None:
                        querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0],machine.encrypttype)
                        status1 = querysystemconfigure.SendAndReceive()
                        if status1 != 0:
                            line = False
                            tree = False
                            tranmission = True
                            admission = False
                            vip = False
                            fragment = False
                            ipaddr = ''
                            ipmask = ''
                        else:
                            linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=0).first()
                            line = linkstatus.line_work_enable
                            tree = linkstatus.stp_state
                            tranmission = linkstatus.global_forward_policy
                            admission = linkstatus.is_allowed_access
                            vip = linkstatus.virtual_ip_enabled
                            fragment = linkstatus.post_fragment_enabled
                            ipaddr = linkstatus.ipaddr
                            ipmask = linkstatus.ipmask
                        break            
                for eachone in [natip, natipaddr, natipmask]:
                    if eachone == None:
                        getnatconfig = privatenetwork.CGetNatConfig(id, machine.ip,[0],machine.encrypttype)
                        status2 = getnatconfig.SendAndReceive()
                        if status2 != 0:
                            natip = False
                            natipaddr = ''
                            natipmask = ''
                        else:
                            linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=0).first()
                            natip = linkstatus.nat_ip_enabled
                            natipaddr = linkstatus.nat_ipaddr
                            natipmask = linkstatus.nat_ipmask                            
                        break
                if admission == None:
                    getallowedaccessstate = privatenetwork.CGetAllowedAccessState(id,machine.ip,machine.encrypttype)
                    status3 = getallowedaccessstate.SendAndReceive()
                    if status3 != 0:
                        admission = False
                    else:
                        linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=0).first()
                        admission = linkstatus.is_allowed_access                             
            route = DRouteTable.query.filter_by(id=id,lino=0).all()
            return render_template('privatesystem.html',machine=machine,line=line,natip=natip,tree=tree,tranmission=tranmission,admission=admission,routes=route,fragment=fragment,vip=vip,ipaddr=ipaddr,ipmask=ipmask,natipaddr=natipaddr,natipmask=natipmask)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatesystem/net2/<int:id>', methods=['GET'])
    def private_net2(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            machine = Cipermachine.query.filter_by(id=id).first()
            line = False
            natip = False
            vip = False            
            tree = False
            tranmission = True
            admission = False
            fragment = False
            ipaddr = ''
            ipmask = ''
            natipaddr = ''
            natipmask = ''
            querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [1],machine.encrypttype)
            status1 =  querysystemconfigure.SendAndReceive()
            getnatconfig = privatenetwork.CGetNatConfig(id, machine.ip,[0],machine.encrypttype)
            status2 = getnatconfig.SendAndReceive() 
            getallowedaccessstate = privatenetwork.CGetAllowedAccessState(id,machine.ip,machine.encrypttype)
            status3 = getallowedaccessstate.SendAndReceive()               
            if status1 == 0 or status2 == 0 or status3 == 0 :
                linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=1).first()
                if status1 == 0:
                    line = linkstatus.line_work_enable
                    tree = linkstatus.stp_state
                    tranmission = linkstatus.global_forward_policy
                    vip = linkstatus.virtual_ip_enabled
                    fragment = linkstatus.post_fragment_enabled
                    ipaddr = linkstatus.ipaddr
                    ipmask = linkstatus.ipmask
                if status2 == 0:   
                    natip = linkstatus.nat_ip_enabled                        
                    natipaddr = linkstatus.nat_ipaddr
                    natipmask = linkstatus.nat_ipmask
                if status3 == 0:
                    admission = linkstatus.is_allowed_access

                for eachone in [line, tree, tranmission, vip, fragment, ipaddr, ipmask]:
                    if eachone == None:
                        querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [1],machine.encrypttype)
                        status1 = querysystemconfigure.SendAndReceive()
                        if status1 != 0:
                            line = False
                            tree = False
                            tranmission = True
                            admission = False
                            vip = False
                            fragment = False
                            ipaddr = ''
                            ipmask = ''
                        else:
                            linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=1).first()
                            line = linkstatus.line_work_enable
                            tree = linkstatus.stp_state
                            tranmission = linkstatus.global_forward_policy
                            admission = linkstatus.is_allowed_access
                            vip = linkstatus.virtual_ip_enabled
                            fragment = linkstatus.post_fragment_enabled
                            ipaddr = linkstatus.ipaddr
                            ipmask = linkstatus.ipmask 
                        break                   
                for eachone in [natip, natipaddr, natipmask]:
                    if eachone == None:
                        getnatconfig = privatenetwork.CGetNatConfig(id, machine.ip,[1],machine.encrypttype)
                        status2 = getnatconfig.SendAndReceive()
                        if status2 != 0:
                            natip = False
                            natipaddr = ''
                            natipmask = ''
                        else:
                            linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=1).first()
                            natip = linkstatus.nat_ip_enabled
                            natipaddr = linkstatus.nat_ipaddr
                            natipmask = linkstatus.nat_ipmask                            
                        break
                if admission == None:
                    getallowedaccessstate = privatenetwork.CGetAllowedAccessState(id,machine.ip,machine.encrypttype)
                    status3 = getallowedaccessstate.SendAndReceive()
                    if status3 != 0:
                        admission = False
                    else:
                        linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=1).first()
                        admission = linkstatus.is_allowed_access                             
            route = DRouteTable.query.filter_by(id=id,lino=1).all()
            return render_template('privatesystem2.html',machine=machine,line=line,natip=natip,tree=tree,tranmission=tranmission,admission=admission,routes=route,fragment=fragment,vip=vip,ipaddr=ipaddr,ipmask=ipmask,natipaddr=natipaddr,natipmask=natipmask)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatesystem/enableline/<int:id>',methods=['POST'])
    def private_system_enableline(id):
        whether = int(request.form['whether'])
        linenumber = int(request.form['linenumber'])
        machine = Cipermachine.query.filter_by(id=id).first() 
        parameters = [whether, linenumber]
        enablelink = privatenetwork.CEnablelink(id,machine.ip,parameters,machine.encrypttype)
        status = enablelink.SendAndReceive()
        return str(status)

    ###enable nat ip
    @app.route('/privateequipment/privatesystem/enablenatip/<int:id>', methods=['POST'])
    def private_system_enablenatip(id):
        machine = Cipermachine.query.filter_by(id=id).first()        
        whether = int(request.form['whether'])
        linenumber = int(request.form['linenumber'])
        parameters = [whether,linenumber]
        enablenat = privatenetwork.CEnableNat(id,machine.ip,parameters,machine.encrypttype)
        status = enablenat.SendAndReceive()
        if status == 0:
            getnatconfig = privatenetwork.CGetNatConfig(id,machine.ip,parameters,machine.encrypttype) 
            status2 = getnatconfig.SendAndReceive()
            return str(status)
        else:   
            return str(status)
    
    ### global forward policy
    @app.route('/privateequipment/privatesystem/transition/<int:id>', methods=['POST'])
    def private_system_transition(id):
        whether = int(request.form['whether'])
        linenumber = int(request.form['linenumber'])
        machine = Cipermachine.query.filter_by(id=id).first() 
        '''getglobalforwardpolicy = privatenetwork.CGetGlobalForwardPolicy(id,machine.ip,machine.encrypttype)
        status = getglobalforwardpolicy.SendAndReceive()'''
        parameters = [whether,linenumber]
        setglobalforwardpolicy = privatenetwork.CSetGlobalForwardPolicy(id,machine.ip,parameters,machine.encrypttype)
        status = setglobalforwardpolicy.SendAndReceive()
        return str(status)

    ### allowed access state
    @app.route('/privateequipment/privatesystem/visit/<int:id>', methods=['POST'])
    def private_system_visit(id):
        machine = Cipermachine.query.filter_by(id=id).first()         
        whether = int(request.form['whether'])
        linenumber = int(request.form['linenumber'])
        parameters = [whether,linenumber]
        setallowedaccessstate = privatenetwork.CSetAllowedAccessStatus(id,machine.ip,parameters,machine.encrypttype)
        status = setallowedaccessstate.SendAndReceive()
        if status == 0:
            getallowedaccessstate = privatenetwork.CGetAllowedAccessState(id,machine.ip,machine.encrypttype)
            getallowedaccessstate.SendAndReceive()        
        return str(status)

    @app.route('/privateequipment/privatesystem/addnatip/<int:id>',methods=['POST'])
    def private_system_addnatip(id):
        ip = request.form['ip'].encode('utf-8')
        mask = request.form['mask'].encode('utf-8')
        legal1 = check_ip(ip)
        legal2 = check_ip(mask)
        if legal1 & legal2 == 0:
            return "-3"
        else:
            linenumber = int(request.form['linenumber'])
            machine = Cipermachine.query.filter_by(id=id).first() 
            parameters = [ip.encode('utf-8'),mask.encode('utf-8'),linenumber]    
            setnatipaddr = privatenetwork.CSetNatIPAddress(id, machine.ip, parameters,machine.encrypttype)
            status = setnatipaddr.SendAndReceive()
            return str(status)

    @app.route('/privateequipment/privatesystem/enabletree/<int:id>', methods=['POST'])
    def private_system_enabletree(id):
        whether = int(request.form['whether'])
        linenumber = int(request.form['linenumber'])
        parameters=[whether,linenumber]
        machine = Cipermachine.query.filter_by(id=id).first()
        setstp = privatenetwork.CSetSTP(id,machine.ip,parameters,machine.encrypttype)
        status = setstp.SendAndReceive()
        return str(status)

    ### get nat configure
    @app.route('/privateequipment/privatesystem/getnatconfigure/<int:id>',methods=['POST'])
    def private_system_getnetconfigure(id):
        linenumber = int(request.form['linenumber'])
        machine = Cipermachine.query.filter_by(id=id).first()  
        parameters = [linenumber]
        getnatconfig = privatenetwork.CGetNatConfig(id,machine.ip,parameters,machine.encrypttype) 
        status = getnatconfig.SendAndReceive()   
        return str(status)

    @app.route('/privateequipment/privatesystem/addroute/<int:id>',methods=['POST'])
    def private_system_addroute(id):
        ip = request.form['ip'] 
        mask = request.form['mask']
        gateway = request.form['gateway'] 
        style = int(request.form['style'])
        legal1 = check_ip(ip)
        legal2 = check_ip(mask)
        legal3 = check_ip(gateway)
        if legal1 & legal2 & legal3 == 0:
            return "-3"
        else:
            linenumber = int(request.form['linenumber'])
            machine = Cipermachine.query.filter_by(id=id).first()  
            parameters = [style, ip.encode('utf-8'),mask.encode('utf-8'),gateway.encode('utf-8'),linenumber]
            setroute = privatenetwork.CSetRoute(id,machine.ip,parameters,machine.encrypttype)
            status = setroute.SendAndReceive()
            return str(status)


    @app.route('/privateequipment/privatesystem/refreshroute/<int:id>',methods=['POST'])
    def private_system_refreshroute(id):
        linenumber = int(request.form['linenumber'])
        machine = Cipermachine.query.filter_by(id=id).first()
        querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [linenumber],machine.encrypttype)
        status = querysystemconfigure.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/deleteroute/<int:id>',methods=['POST'])
    def private_system_deleteroute(id):
        routenumber = int(request.form['id']) -1
        style = request.form['style']
        if style == "网络路由":
            keyword = 0
        elif style == "主机路由":
            keyword = 1
        elif style == "默认路由":
            keyword = 2
        else:
            return "-4"
        linenumber = int(request.form['linenumber'])
        parameters = [keyword,routenumber,linenumber]
        machine = Cipermachine.query.filter_by(id=id).first()  
        deleteroute = privatenetwork.CDeleteRoute(id, machine.ip,parameters,machine.encrypttype)
        status = deleteroute.SendAndReceive()
        if status == 0:
            querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [linenumber],machine.encrypttype)
            status = querysystemconfigure.SendAndReceive()
        return str(status)






##  2）、配置VLAN
    @app.route('/privateequipment/privatesystem/vlan/<int:id>',methods=['GET'])
    def private_system_net(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            vlan = False
            addr = False
            line = False
            lineinfo = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id)          
            info = lineinfo.filter_by(lino=0).first()
            info2 = lineinfo.filter_by(lino=1).first()
            machine = Cipermachine.query.filter_by(id=id).first()
            if (info == None) or (info != None and (info.vlan_bind_channel == None or info.multi_ip == None)):
                querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0],machine.encrypttype)
                status =  querysystemconfigure.SendAndReceive()
                if status == 0:
                    info = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=0).first()
                    if info != None:
                        if info.vlan_bind_channel != None:
                            vlan = info.vlan_bind_channel
                        if info.multi_ip != None:
                            addr = info.multi_ip
            else:
                vlan = info.vlan_bind_channel
                addr = info.multi_ip
            vlans = models.DVlanList.query.filter_by(id=id,lino=0).order_by(models.DVlanList.vid).all()
            if (info2 == None) or (info2 != None and info2.line_work_enable == None):
                querysystemconfigure2 = privatesystem.CQuerySystemInfo(id, machine.ip, [1],machine.encrypttype)
                status2 = querysystemconfigure2.SendAndReceive()
                if status2 == 0:
                    info2 = info = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=1).first()
                    if info2 != None:
                        if info2.line_work_enable != None:
                            line = info2.line_work_enable
            else:
                line = info2.line_work_enable
            return render_template('privatesystem/systemvlan.html',machine=machine,vlans=vlans,addr=addr, vlan=vlan, line=line)
        else:
            return redirect('/')


    @app.route('/privateequipment/privatesystem/vlan2/<int:id>',methods=['GET'])
    def private_system_net2(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            vlan = False
            addr = False            
            info = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=1).first()
            machine = Cipermachine.query.filter_by(id=id).first()
            if (info == None) or (info != None and (info.vlan_bind_channel == None or info.multi_ip == None)):
                querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [1],machine.encrypttype)
                status =  querysystemconfigure.SendAndReceive()
                if status != 0:
                    info = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=1).first()
                    if info != None:
                        if info.vlan_bind_channel != None:
                            vlan = info.vlan_bind_channel
                        if info.multi_ip != None:
                            addr = info.multi_ip
            else:
                vlan = info.vlan_bind_channel
                addr = info.multi_ip
            vlans = models.DVlanList.query.filter_by(id=id, lino=1).all()
            return render_template('privatesystem/systemvlan2.html',machine=machine,vlans=vlans)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatesystem/enableaddr/<int:id>',methods=['POST'])
    def private_system_enableaddr(id):

        machine = Cipermachine.query.filter_by(id=id).first()
        ip = machine.ip.encode('utf-8')       
        whether = int(request.form['whether'])
        linenumber = int(request.form['linenumber'])
        parameter = [whether,linenumber]
        setmultiip = privatevlan.CSetMultiIP(id,ip,parameter,machine.encrypttype)
        status = setmultiip.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/addvlan/<int:id>',methods=['POST'])
    def private_system_addvlan(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        belog = int(request.form['belog'])
        ARP = int(request.form['APR'])
        linenumber = int(request.form['linenumber'])
        vlanid = int(request.form['vlanid'])
        subnet = request.form['subnet']
        submask = request.form['submask']
        outroute = request.form['outroute']
        enter = request.form['enter']
        legal1 = check_ip(subnet)
        legal2 = check_ip(submask)
        legal3 = check_ip(outroute)
        legal4 = check_ip(enter)
        if legal1 & legal2 & legal3 & legal4 == 0:
            return "-3"
        else:
            parameters = [vlanid, subnet.encode('utf-8'), submask.encode('utf-8'), outroute.encode('utf-8'), enter.encode('utf-8'), belog, linenumber, ARP]
            addvlan = privatevlan.CAddVlan(id, machine.ip, parameters,machine.encrypttype)
            status = addvlan.SendAndReceive()
            if status == 0:
                getvlanlist = privatevlan.CGetVlanList(id, machine.ip, [linenumber],machine.encrypttype)
                getvlanlist.SendAndReceive()
            return str(status)

    @app.route('/privateequipment/privatesystem/refreshvlan/<int:id>',methods=['POST'])
    def private_system_refreshvlan(id):
        linenumber = int(request.form['linenumber'])
        machine = Cipermachine.query.filter_by(id=id).first()
        getvlanlist = privatevlan.CGetVlanList(id, machine.ip, [linenumber],machine.encrypttype)
        status = getvlanlist.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/deletevlan/<int:id>',methods=['POST'])
    def private_system_deletevlan(id):
        vlanid = int(request.form['vlanid'])
        linenumber = int(request.form['linenumber'])
        machine = Cipermachine.query.filter_by(id=id).first()
        deletevlan = privatevlan.CDeleteVlan(id, machine.ip, [vlanid, linenumber],machine.encrypttype)
        status = deletevlan.SendAndReceive()
        if status == 0:
            getvlanlist = privatevlan.CGetVlanList(id, machine.ip, [linenumber],machine.encrypttype)
            getvlanlist.SendAndReceive()            
        return str(status)


##  3）、配置Mac地址
    @app.route('/privateequipment/privatesystem/mac/<int:id>',methods=['GET'])
    def private_system_mac(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            lino = 0
            route_mac = ['','','','','','']
            switch_mac = ['','','','','','']
            line = False
            machine = Cipermachine.query.filter_by(id=id).first()
            getmac = privatenetwork.CGetMacInfo(id,machine.ip,[lino],machine.encrypttype)
            status = getmac.SendAndReceive()
            if status == 0:
                linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=lino).first()
                if linkstatus != None:
                    if linkstatus.route_mac != None:
                        route_mac = linkstatus.route_mac.split(':')
                    if linkstatus.switch_mac != None:
                        switch_mac = linkstatus.switch_mac.split(':')
            querysystemconfigure2 = privatesystem.CQuerySystemInfo(id, machine.ip, [1], machine.encrypttype)
            status2 = querysystemconfigure2.SendAndReceive()
            if status2 == 0:
                info2 = info = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id, lino=1).first()
                if info2 != None:
                    if info2.line_work_enable != None:
                        line = info2.line_work_enable
            return render_template('privatesystem/systemmac.html',machine=machine, route_mac=route_mac, switch_mac=switch_mac,line=line)
        else:
            return redirect('/')

    @app.route('/privateequipment/privatesystem/mac2/<int:id>',methods=['GET'])
    def private_system_mac2(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            lino = 1
            route_mac = ['','','','','','']
            switch_mac = ['','','','','','']
            machine = Cipermachine.query.filter_by(id=id).first()
            getmac = privatenetwork.CGetMacInfo(id,machine.ip,[lino],machine.encrypttype)
            status = getmac.SendAndReceive()
            if status == 0:
                linkstatus = models.DPrivateEquipmentLinkInfo.query.filter_by(id=id,lino=lino).first()
                    if linkstatus != None:
                        if linkstatus.route_mac != None:
                            route_mac = linkstatus.route_mac.split(':')
                        if linkstatus.switch_mac != None:
                            switch_mac = linkstatus.switch_mac.split(':')
            return render_template('privatesystem/systemmac2.html', machine= machine , route_mac=route_mac,switch_mac=switch_mac)
        else :
            return redirect ( '/' )


    @app.route('/privateequipment/privatesystem/edit/<int:id>',methods=['POST'])
    def private_system_setmac(id):
        select = int(request.form['select'])
        linenumber = int(request.form['linenumber'])
        print linenumber
        if select == 0:
            routemac = request.form['routemac1'] + ':' + request.form['routemac2'] + ':' + request.form['routemac3'] + ':' + request.form['routemac4'] + ":" + request.form['routemac5'] + ":" + request.form['routemac6']
            legal1 = check_mac(routemac)
            if legal1 == 0:
                return "-3"
            else:
                switchmac = request.form['switchmac1'] + ':' + request.form['switchmac2'] + ':' + request.form['switchmac3'] + ':' + request.form['switchmac4'] + ":" + request.form['switchmac5'] + ":" + request.form['switchmac6']
                machine = Cipermachine.query.filter_by(id=id).first()
                setmacinfo = privatenetwork.CSetMacInfo(id, machine.ip, [linenumber, routemac.encode('utf-8'), switchmac.encode('utf-8')],machine.encrypttype)
                status = setmacinfo.SendAndReceive()
                return str(status)
                if status == 0:
                    getmac = privatenetwork.CGetMacInfo(id,machine.ip,[linenumber],machine.encrypttype)
                    status2 = getmac.SendAndReceive()
                    return str(status)
                else:    
                    return str(status)
        elif select == 1:
            switchmac = request.form['switchmac1'] + ':' + request.form['switchmac2'] + ':' + request.form['switchmac3'] + ':' + request.form['switchmac4'] + ":" + request.form['switchmac5'] + ":" + request.form['switchmac6']
            legal2 = check_mac(switchmac)
            if legal2 == 0:
                return "-3"
            else:
                routemac = request.form['routemac1'] + ':' + request.form['routemac2'] + ':' + request.form['routemac3'] + ':' + request.form['routemac4'] + ":" + request.form['routemac5'] + ":" + request.form['routemac6']
                machine = Cipermachine.query.filter_by(id=id).first()
                setmacinfo = privatenetwork.CSetMacInfo(id, machine.ip, [linenumber, routemac.encode('utf-8'), switchmac.encode('utf-8')],machine.encrypttype)
                status = setmacinfo.SendAndReceive()
                #print "###########routemac = ", routemac
                #print "###########switchmac = ",switchmac
                return str(status)
                if status == 0:
                    getmac = privatenetwork.CGetMacInfo(id,machine.ip,[linenumber],machine.encrypttype)
                    status2 = getmac.SendAndReceive()
                    return str(status)
                else:    
                    return str(status)
        elif select == 2:
            routemac = request.form['routemac1'] + ':' + request.form['routemac2'] + ':' + request.form['routemac3'] + ':' + request.form['routemac4'] + ":" + request.form['routemac5'] + ":" + request.form['routemac6']
            switchmac = request.form['switchmac1'] + ':' + request.form['switchmac2'] + ':' + request.form['switchmac3'] + ':' + request.form['switchmac4'] + ":" + request.form['switchmac5'] + ":" + request.form['switchmac6']
            legal3 = check_mac(routemac)
            legal4 = check_mac(switchmac)
            #print "###########routemac = ", routemac
            #print "###########switchmac = ",switchmac
            if legal3 & legal4 == 0:
                return "-3"
            else:
                machine = Cipermachine.query.filter_by(id=id).first()
                setmacinfo = privatenetwork.CSetMacInfo(id, machine.ip, [linenumber, routemac.encode('utf-8'), switchmac.encode('utf-8')],machine.encrypttype)
                status = setmacinfo.SendAndReceive()
                return str(status)
                if status == 0:
                    getmac = privatenetwork.CGetMacInfo(id,machine.ip,[linenumber],machine.encrypttype)
                    status2 = getmac.SendAndReceive()
                    return str(status)
                else:    
                    return str(status)


    @app.route('/privateequipment/privatesystem/refresh/<int:id>',methods=['POST'])
    def private_system_refresh(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        linenumber = int(request.form['linenumber'])
        getmac = privatenetwork.CGetMacInfo(id,machine.ip,[linenumber],machine.encrypttype)
        status = getmac.SendAndReceive()      
        return str(status)

##  4）、互备装置
    @app.route('/privateequipment/privatesystem/interation/<int:id>',methods=['GET'])
    def private_system_interation(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            isstandalone = True
            ismaster = True
            masterchange = False
            machine = Cipermachine.query.filter_by(id=id).first()
            
            querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0], machine.encrypttype)
            status = querysystemconfigure.SendAndReceive()
                if status == 0:
                    equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
                    if equipmentstatus != None:
                        if equipmentstatus.isstandalone != None:
                            isstandalone = equipmentstatus.isstandalone
                        if equipmentstatus.ismaster != None:
                            ismaster = equipmentstatus.ismaster
                        if equipmentstatus.one_ip_hotswap != None:
                            masterchange = equipmentstatus.one_ip_hotswap
            return render_template('privatesystem/systeminteration.html',machine=machine,isstandalone=isstandalone, ismaster=ismaster, masterchange=masterchange)
        else:
            return redirect('/')


    @app.route('/privateequipment/privatesystem/setrunmode/<int:id>',methods=['POST'])
    def set_runmode(id):
        runmode = int(request.form['runmode'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setstandalone = privatesystem.CSetStandAlone(id, machine.ip, [runmode],machine.encrypttype)
        status = setstandalone.SendAndReceive()
        return str(status)


    @app.route('/privateequipment/privatesystem/setinteration/<int:id>',methods=['POST'])
    def set_interation(id):
        role = int(request.form['role'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setmastermodel = privatesystem.CSetMasterModel(id, machine.ip, [role],machine.encrypttype)
        status = setmastermodel.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/submaninchange/<int:id>',methods=['POST'])
    def private_system_submainchange(id):
        whether = int(request.form['whether'])
        machine = Cipermachine.query.filter_by(id=id).first()
        masterchange = privatesystem.CEnableDoubleMachine(id, machine.ip, [whether],machine.encrypttype)
        status = masterchange.SendAndReceive()
        return str(status)        



##  5）、杂项配置
    @app.route('/privateequipment/privatesystem/sundry/<int:id>',methods=['GET'])
    def private_system_sundry(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            machine = Cipermachine.query.filter_by(id=id).first()
            equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
            dk_encrypt_times_max = ''
            dk_lifetime = ''
            dk_retry_interval = ''
            sping_send_interval = ''
            sping_response_timeout = ''
            work_model = 0
            secplateformflag = True
            no_alarm = True
            IPSEC = ''
            equipment_time = '' 
            querysystemconfigure = privatesystem.CQuerySystemInfo(id, machine.ip, [0],machine.encrypttype)
            status = querysystemconfigure.SendAndReceive()
            equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
            if equipmentstatus != None:
                if equipmentstatus.dk_encrypt_times_max != None:
                    dk_encrypt_times_max = equipmentstatus.dk_encrypt_times_max
                if equipmentstatus.dk_lifetime != None:
                    dk_lifetime = equipmentstatus.dk_lifetime
                if equipmentstatus.dk_retry_interval != None:
                    dk_retry_interval = equipmentstatus.dk_retry_interval
                if equipmentstatus.sping_response_timeout != None:
                    sping_response_timeout = equipmentstatus.sping_response_timeout
                if equipmentstatus.sping_send_interval != None:
                    sping_send_interval = equipmentstatus.sping_send_interval
                if equipmentstatus.work_model != None:
                    work_model = equipmentstatus.work_model
            if equipmentstatus == None or equipmentstatus.secplateformflag == None:
                getplateformstate = privatesundry.CGetPlateformState(id, machine.ip,machine.encrypttype) 
                status = getplateformstate.SendAndReceive()
                if status == 0:
                    equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
                    if equipmentstatus != None:
                        if equipmentstatus.secplateformflag != None:
                            secplateformflag = equipmentstatus.secplateformflag
            else:
                secplateformflag = equipmentstatus.secplateformflag
            if equipmentstatus == None or equipmentstatus.ipsec_parameter == None:
                getipsecpara = privatesundry.CGetIPsecParameter(id, machine.ip,machine.encrypttype)
                status = getipsecpara.SendAndReceive()
                if status == 0:
                    equipmentstatus = models.DPrivateEquipmentCommonInfo.query.filter_by(id=id).first()
                    if equipmentstatus != None:
                        if equipmentstatus.ipsec_parameter != None:
                            IPSEC = equipmentstatus.ipsec_parameter
            else:
                IPSEC = equipmentstatus.ipsec_parameter
           
            getsystemtime = privatesundry.CGetSystemTime(id, machine.ip,machine.encrypttype)
            status, systemtime = getsystemtime.SendAndReceive()
            if status == 0:
                equipment_time = systemtime
            now = time.localtime()
            local_date = time.strftime('%Y-%m-%d', now)
            local_time = time.strftime('%H:%M:%S', now)
            return render_template('privatesystem/systemsundry.html',machine=machine,dk_encrypt_times_max = dk_encrypt_times_max, \
               dk_lifetime = dk_lifetime, dk_retry_interval = dk_retry_interval, sping_send_interval = sping_send_interval, \
               sping_response_timeout = sping_response_timeout, work_model = work_model, secplateformflag =secplateformflag, \
               IPSEC = IPSEC, local_date=local_date, local_time=local_time, equipment_time=equipment_time)
        else:
            return redirect('/')
           
    @app.route('/privateequipment/privatesystem/setdatetime/<int:id>',methods=['POST'])
    def private_system_setdatatime(id):
        date = request.form['date'].encode('utf-8').split('-')
        time = request.form['time'].encode('utf-8').split(':')
        try:
            year = int(date[0])
            month = int(date[1])
            day = int(date[2])
            hour = int(time[0])
            minute = int(time[1])
            second = int(00)
        except:
            return '-3'

        if len(str(year))>4:
            return '-3'
        machine = Cipermachine.query.filter_by(id=id).first()

        parameters = [year, month, day, hour, minute, second]
        setsystemtime = privatesundry.CSetSystemTime(id, machine.ip, parameters,machine.encrypttype)
        status = setsystemtime.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/setworkmode/<int:id>',methods=['POST'])
    def private_system_setworkmode(id):
        workmode = int(request.form['workmode'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setworkmode = privatesundry.CSetWorkModel(id,machine.ip, [workmode],machine.encrypttype)
        status = setworkmode.SendAndReceive()           
        return str(status)

    @app.route('/privateequipment/privatesystem/setmaxencrypt/<int:id>',methods=['POST'])
    def private_system_setmaxencrypt(id):
        maxencrypt = int(request.form['maxencrypt'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setmacencrypttimes = privatesundry.CSetMaxEncryptTimes(id,machine.ip, [maxencrypt * 10000],machine.encrypttype)
        status = setmacencrypttimes.SendAndReceive()       
        return str(status)

    @app.route('/privateequipment/privatesystem/setmaxcycle/<int:id>', methods=['POST'])
    def private_system_setmaxcycle(id):
        period = int(request.form['period'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setlifecyc  = privatesundry.CSetLongestSurvivalPeriodofKey(id,machine.ip, [period * 3600],machine.encrypttype)
        status = setlifecyc.SendAndReceive()             
        return str(status)

    @app.route('/privateequipment/privatesystem/settimeout/<int:id>', methods=['POST'])
    def private_system_settimeout(id):
        outtime = int(request.form['outtime'])
        machine = Cipermachine.query.filter_by(id=id).first()
        settimeout  = privatesundry.CSetTimeout(id,machine.ip, [outtime],machine.encrypttype)
        status = settimeout.SendAndReceive()           
        return str(status)

    @app.route('/privateequipment/privatesystem/setinterval/<int:id>', methods=['POST'])
    def private_system_setinterval(id):
        spingtime = int(request.form['spingtime'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setspinginterval = privatesundry.CSetSpingSendInterval(id,machine.ip, [spingtime],machine.encrypttype)
        status = setspinginterval.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/setspingouttime/<int:id>', methods=['POST'])
    def private_system_setspingouttime(id):
        spingouttime = int(request.form['spingouttime'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setresponsetimeout = privatesundry.CSetSpingResponseTimeout(id,machine.ip, [spingouttime],machine.encrypttype)
        status = setresponsetimeout.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/enablesecplate/<int:id>',methods=['POST'])
    def private_system_setsecplate(id):
        whether = int(request.form['whether'])
        machine = Cipermachine.query.filter_by(id=id).first()
        setplateformstate  = privatesundry.CSetPlateformState(id, machine.ip, [whether],machine.encrypttype) 
        status = setplateformstate.SendAndReceive()
        if status == 0:
            getplateformstate = privatesundry.CGetPlateformState(id, machine.ip,machine.encrypttype)
            getplateformstate.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/setipsec/<int:id>', methods=['POST'])
    def private_system_setipsec(id):
        parameter = request.form['parameter'].encode('utf-8')
        part = parameter.split(',')
        if len(part) != 2:
            return "-3"
        else:
            part1 = part[0]
            part2 = part[1]
            if part1.isdigit() & part2.isdigit() == 0:
                return "-3"
            else:
                machine = Cipermachine.query.filter_by(id=id).first()
                setipsecpara = privatesundry.CSetIPsecParameter(id, machine.ip, [parameter],machine.encrypttype)
                status = setipsecpara.SendAndReceive()
                if status == 0:
                    getipsecpara = privatesundry.CGetIPsecParameter(id, machine.ip)
                return str(status)

##  6）、日志服务器配置
    @app.route('/privateequipment/privatesystem/log/<int:id>',methods=['GET'])
    def private_system_log(id):
        IiI1i = Users . query . filter_by ( admin = 2 ) . first ( )
        if IiI1i != None and session . get ( 'admin' ) == IiI1i . admin :
            o0 = Cipermachine . query . filter_by ( id = id ) . first ( )
            ooo = models . DLogServerInfo . query . filter_by ( id = id ) . all ( )
            vlans = db.session.query(models.DVlanList.id,models.DVlanList.vid).filter_by(id=id,lino=0).order_by(models.DVlanList.vid).all()
            vlan2s = db.session.query(models.DVlanList.id,models.DVlanList.vid).filter_by(id=id,lino=1).order_by(models.DVlanList.vid).all()
            return render_template ( 'privatesystem/systemlog.html' , machine = o0 , servers = ooo , vlans=vlans, vlan2s=vlan2s)
        else :
            return redirect ( '/' )

    @app.route('/privateequipment/privatesystem/addlogserver/<int:id>',methods=['POST'])
    def private_system_addlogserver(id):
        ip = request.form['ip']
        port = request.form['port']
        direction = int(request.form['direction'])
        line = int(request.form['line'])
        vlanid = int(request.form['vlanid'])
        legal = check_ip(ip)
        if legal == 0:
            return "-3"
        else:    
            parameters = [ip.encode('utf-8'), port.encode('utf-8'), direction, line, vlanid]
            machine = Cipermachine.query.filter_by(id=id).first()
            addlogserver = privatelog.CAddLogServer(id, machine.ip, parameters,machine.encrypttype)
            status = addlogserver.SendAndReceive()
            if status == 0:
                getloginfo = privatelog.CGetLogServerInfo(id,machine.ip,machine.encrypttype)
                getloginfo.SendAndReceive()
            return str(status)

    @app.route('/privateequipment/privatesystem/reget/<int:id>',methods=['POST'])
    def private_system_reget(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        getloginfo = privatelog.CGetLogServerInfo(id,machine.ip,machine.encrypttype)
        status = getloginfo.SendAndReceive()
        return str(status)

    @app.route('/privateequipment/privatesystem/delete/<int:id>/<int:number>',methods=['POST'])
    def private_system_delete(id,number):
        machine = Cipermachine.query.filter_by(id=id).first()
        deletelogserver = privatelog.CDeleteLogServer(id, machine.ip, [number - 1],machine.encrypttype)
        status = deletelogserver.SendAndReceive()
        if status == 0:
            getloginfo = privatelog.CGetLogServerInfo(id,machine.ip,machine.encrypttype)
            getloginfo.SendAndReceive()
        return str(status)



##  7）、安全管理
    @app.route('/privateequipment/privatesystem/safe/<int:id>',methods=['GET'])
    def private_system_safe(id):
        IiI1i = Users . query . filter_by ( admin = 2 ) . first ( )
        if IiI1i != None and session . get ( 'admin' ) == IiI1i . admin :
            o0 = Cipermachine . query . filter_by ( id = id ) . first ( )
            return render_template ( 'privatesystem/systemsafe.html' , machine = o0 )
        else :
            return redirect ( '/' )

    @app.route('/privateequipment/privatesystem/confbackup/<int:id>',methods=['POST'])
    def private_system_confbackup(id):

        choose = [int(file_type) for file_type in request.form['choose'].strip(',').split(',')]
        print choose
        machine = Cipermachine.query.filter_by(id=id).first()

        configfolder = os.path.join(app.config['CONFIG_FOLDER'], machine.ip.encode('utf-8') + '.cfg')
        if not os.path.exists(configfolder):
             os.makedirs(configfolder, 0777)
        filelist = os.listdir(configfolder)
        for file in filelist:
            os.remove(os.path.join(configfolder, file))
        filename_dict = ['null','device.cfg', 'channel.cfg', 'policy.cfg', 'vlan.cfg', 'device2.cfg']
        dict1 = ['null',"设备配置文件[device]","隧道配置文件[channel]","策略配置文件[policy]","VLAN配置文件[vlan]","设备配置文件[device2]"]
        AlertInfo = ""
        status = 0
        for File_Type in choose:
            #File_Type = 1
            filepath = os.path.join(configfolder, filename_dict[File_Type])        
            if os.path.exists(filepath):
                os.remove(filepath)
            flag = 1
            offset = 0
            while flag == 1:
                backupconfig = privatesecurity.BackupConfigFile(id, machine.ip, [File_Type, offset, filepath],machine.encrypttype)
                status, flag, datalen = backupconfig.SendAndReceive()
                if status != 0:
                    if status == 6:
                        AlertInfo += dict1[File_Type] + "不存在\n"
                    elif status == -2:
                        return jsonify({"status":"-2"})
                    break
                offset = offset + datalen
        zip_name = configfolder + '.zip'
        zipcompress.zip_dir(configfolder, zip_name)
        return  jsonify({"status":AlertInfo, "filepath":'/' + zip_name}) 

## 6、日志管理
    @app.route('/privateequipment/privatelog/<int:id>', methods=['GET'])
    def private_log(id):
        IiI1i = Users . query . filter_by ( admin = 2 ) . first ( )
        if IiI1i != None and session . get ( 'admin' ) == IiI1i . admin :
            o0 = Cipermachine . query . filter_by ( id = id ) . first ( )
            return render_template ( 'privatelog.html' , machine = o0 )
        else :
            return redirect ( '/' )

    @app.route('/privateequipment/checklog/<int:id>',methods=['GET'])
    def check_log(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            machine = Cipermachine.query.filter_by(id = id).first()
            ip = machine.ip.encode('utf-8')
            queryloglenth = operationequipment.CQueryLogLength(id, ip, machine.encrypttype)
            status1, loglength = queryloglenth.SendAndReceive()
            AlertInfo = ""
            if status1 != 0:
                AlertInfo = SwitchErrorCode(status1)
                return render_template('privatelog.html',machine=machine,AlertInfo=AlertInfo)
            page = 1 
            per_page = 15
            if loglength == 0:
                pages = 1
            else:
                pages = int((loglength - 1) / per_page) + 1
            has_prev = False
            has_next = (page < pages)
            class CPagination():
                def __init__(self, has_next, has_prev, pages, per_page,loglength,page):
                    self.has_prev = has_prev
                    self.has_next = has_next
                    self.pages = pages
                    self.per_page = per_page
                    self.loglength = loglength
                    self.page = page
            pagination = CPagination(has_next, has_prev, pages, per_page,loglength, page)
            if page == pages:
                readlog = operationequipment.CReadLog(id,machine.ip,[loglength - pages * per_page  + per_page, 1],machine.encrypttype)
                status,logs = readlog.SendAndReceive()
            else:
                readlog = operationequipment.CReadLog(id,machine.ip,[per_page,loglength - page * per_page + 1],machine.encrypttype)  
                status,logs = readlog.SendAndReceive()
            if status != 0:
                AlertInfo = SwitchErrorCode(AlertInfo)   
            return render_template('privatelog.html',machine=machine, logs=logs[::-1], pagination=pagination, AlertInfo=AlertInfo)        
        else :
            return redirect ( '/' )
            
        
    @app.route('/privateequipment/paginatelog', methods=['GET'])
    def paginatelog():
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            
            id = request.args.get('machineid',1,type=int)
            per_page = 15
            machine = Cipermachine.query.filter_by(id=id).first()        
            page = request.args.get('page',1, type=int)

            loglength = request.args.get('loglength',0,type=int)
            if loglength == 0:
                pages = 1
            else:
                pages = int((loglength - 1) / per_page) + 1                
            has_prev = (pages > 1)
            has_next = (page < pages)
            class CPagination():
                def __init__(self, has_next, has_prev, pages, per_page,loglength,page):
                    self.has_prev = has_prev
                    self.has_next = has_next
                    self.pages = pages
                    self.per_page = per_page
                    self.loglength = loglength
                    self.page = page
            pagination = CPagination(has_next, has_prev, pages, per_page,loglength,page)   
            if page == pages:
                readlog = operationequipment.CReadLog(id,machine.ip,[loglength - pages * per_page  + per_page, 1], machine.encrypttype)
                status,logs = readlog.SendAndReceive()
            else:
                readlog = operationequipment.CReadLog(id,machine.ip,[per_page,loglength - page * per_page + 1], machine.encrypttype)  
                status,logs = readlog.SendAndReceive()
            AlertInfo = ""
            if status != 0: 
                AlertInfo = SwitchErrorCode(status)
        return render_template('privatelog.html',machine=machine, logs=logs[::-1], pagination=pagination,AlertInfo=AlertInfo)
        else:
            return redirect('/')

    @app.route('/privateequipment/downloadlog/<int:id>',methods=['POST'])
    def private_downloadlog(id):
        machine = Cipermachine.query.filter_by(id=id).first()
        logs = models.DMachineLog.query.filter_by(id=id).all()
        for log in logs:
            db.session.delete(log)
        db.session.commit()

        queryloglenth = operationequipment.CQueryLogLength(id, machine.ip,machine.encrypttype)
        status, loglength = queryloglenth.SendAndReceive()
        logs = []
        returnCode = status
        if status == 0:
            startnumber = 1
            eachlen = 30
            while loglength > 0:
                if loglength <= eachlen:
                    readlog = operationequipment.CReadLog(id, machine.ip, [loglength, startnumber],machine.encrypttype)
                    status,log = readlog.SendAndReceive()
                    if status != 0:
                        returnCode = -4
                        break
                    logs = logs + log
                    break
                else:
                    readlog = operationequipment.CReadLog(id, machine.ip, [eachlen, startnumber],machine.encrypttype)
                    loglength = loglength - eachlen
                    startnumber = startnumber + eachlen
                    status,log = readlog.SendAndReceive()
                    if status != 0:
                        returnCode = -4
                        break
                    logs = logs + log       
        db.session.add_all(logs)
        db.session.commit()
        return str(returnCode) 

    @app.route('/privateequipment/backuplog/<int:id>',methods=['GET'])
    def backup_log(id):
        user2 = Users.query.filter_by(admin=2).first()
        if user2 != None and session.get('admin') == user2.admin:
            import csv
            from flask import make_response
            
            machine = Cipermachine.query.filter_by(id=id).first()
            loglist = [['时间'.decode('utf-8').encode('gbk'),'类型'.decode('utf-8').encode('gbk'),'信息'.decode('utf-8').encode('gbk')]]

            logs = models.DMachineLog.query.filter_by(id=id).all()
            for log in logs:
                loglist.append([log.time.decode('utf-8').encode('gbk'), log.style.decode('utf-8').encode('gbk'), log.content.decode('utf-8').encode('gbk')])
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'systemlog.csv')
            logfile = open(filepath,'wb')
            cs = csv.writer(logfile, dialect='excel')
            cs.writerows(loglist)

            logfile.close()
            return_file = open(filepath, 'rb')
            os.chmod(filepath,777)
            response = make_response(return_file.read(),200)
            response.headers['Content-Description'] = 'File Transfer'
            response.headers['Cache-Control'] = 'no-cache'
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = 'attachment; filename=%s' % 'systemlog.csv' 
            
            return_file.close()
            return response
        else :
            return redirect ( '/' ) 


    @app.route('/privateequipment/cleanlog/<int:id>',methods=['POST'])
    def clean_log(id):

        machine = Cipermachine.query.filter_by(id=id).first()
        deletelog = privatelog.CDeleteLog(id, machine.ip,machine.encrypttype)
        status = deletelog.SendAndReceive()
        return str(status)        
