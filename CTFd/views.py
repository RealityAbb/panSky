# coding=utf-8
from flask import current_app as app, render_template, render_template_string, request, redirect, abort, jsonify, json as json_mod, url_for, session, send_from_directory
from CTFd.utils import authed, allowed_file, sha512, judge_result, check_ip
from CTFd import initial, ukey,Transport
from CTFd.models import db, Users, Certificates,LeadMachine,Flag,LMIPAddr,LMRoute, DLeadMachineCert, Cipermachine, Terminallogs,Tree, EquipmentsStatus,UploadCertificates

from jinja2.exceptions import TemplateNotFound
from passlib.hash import bcrypt_sha256
from collections import OrderedDict
from werkzeug.utils import secure_filename
from flask import current_app as app
import base64
import logging
import os
import shutil
import re
import sys
import json
import hashlib
import os
import datetime
import time
import chardet
import socket
import struct
import MySQLdb
from generalfunction import SwitchErrorCode
authority = app.config['MYSQL_USER']
password = app.config['MYSQL_PASSWORD']
name = app.config['DATEBASE_NAME']
reload(sys)
sys.setdefaultencoding('utf-8')

def init_views(app):
    @app.before_request
    def csrf():
        pass
        # if authed() and request.method == "POST":
        #     if session['nonce'] != request.form.get('nonce'):
        #         # abort(403)
        #         session.clear()
        #         return redirect('/login')
        # if request.method == "GET" and request.path[0:15] == "/static/uploads":
        #     if not authed():
        #         return redirect('/home')

    def DeleteData(sql):
        db = MySQLdb.connect("localhost",authority,password,name,charset='utf8' )
        cursor = db.cursor()
        cursor.execute(sql)
        cursor.close()
        db.commit()
        db.close()


    @app.route('/setup', methods=['GET', 'POST'])
    def setup():
        #if not is_setup():
            if request.method == 'POST':
                errors = []
                ## Admin user
                name = request.form['name']
                adminname = app.config['ADMINNAME']
                adminpassword = app.config['ADMINPASSWORD']
                epassword = request.form['epassword']
                password = base64.decodestring(epassword)
                if name == adminname and bcrypt_sha256.verify(password, adminpassword):
                    session.parmanent = False
                    session['username'] = adminname
                    session['password'] = adminpassword
                    session['admin'] = 0
                    session['nonce'] = sha512(os.urandom(10))
                    flag = Flag.query.first()
                    if flag == None:
                        addlmflag=0
                        createkeyflag=0
                        exportlmcertflag=0
                        configIPflag=0
                        restartflag=0
                        configrouteflag=0
                        importCAflag=0
                        importsyscertflag=0
                        initialUSBKeyflag=0
                        importUSBKeyflag=0
                        flag = Flag(addlmflag,createkeyflag,exportlmcertflag,restartflag,configIPflag,configrouteflag,importCAflag,importsyscertflag,initialUSBKeyflag,importUSBKeyflag)
                        db.session.add(flag)
                        db.session.commit()
                        flag = Flag.query.first()
                    count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                    if count<1:
                        return redirect('/initial1')
                    elif count<4:
                        return redirect('/initial2')
                    elif count<5:
                        return redirect('/initial3')
                    elif count<6:
                        return redirect('/initial4')
                    elif count<7:
                        return redirect('/initial5')
                    elif count<8:
                        return redirect('/initial6')
                    elif count<10:
                        return redirect('/initial8')
                    else:
                        return redirect('/initial1')
                else:
                    errors.append("用户名或者密码错误。")
                    db.session.close()
                return render_template('setup.html', errors=errors)
            else:
                db.session.close()
                return render_template('setup.html')

    @app.route('/finishinit',methods=['POST','GET'])
    def finishinit():
        return render_template('base.html')
    
    @app.route('/initial1',methods=['GET'])
    def addleadmachine():
        if session.get('admin') == 0:
            leadmachine = LeadMachine.query.first()
            ipaddress = ""
            if leadmachine != None:
                ipaddress = leadmachine.lmip
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            return render_template('initial1.html', ipaddress = ipaddress, count = count)
        else:
            return redirect('/setup') 

    @app.route('/initial1/addlm',methods=['POST'])
    def addlm():
        lmip = request.form['lmip']
        outtime = 3
        resendtime = 1
        leadmachines = LeadMachine.query.first()
        if leadmachines == None:
            newrecord = LeadMachine(lmip,outtime,resendtime)            
            db.session.add(newrecord)
            db.session.commit()
        else:
            leadmachines.lmip = lmip
            db.session.add(leadmachines)
            db.session.commit()
       
        flag = Flag.query.first()
        flag.addlmflag = 1
        db.session.add(flag)
        db.session.commit()

        count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
        return render_template('initial1.html', ipaddress = lmip, count = count,AlertInfo="设置成功！")

    @app.route('/initial2',methods=['GET'])
    def preleadmachine():
        if session.get('admin') == 0:
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            db.session.close()
            return render_template('initial2.html',flag = flag, count = count)
        else:
            return redirect('/setup') 
    
    @app.route('/initial2/prelm',methods=['POST'])
    def prelm():
        if request.method == 'POST':
            country = request.form['country'].decode('utf-8').encode('gbk')
            province = request.form['province'].decode('utf-8').encode('gbk')
            city = request.form['city'].decode('utf-8').encode('gbk')
            organ = request.form['organ'].encode('utf-8')
            depart = request.form['depart'].encode('utf-8')
            name = request.form['name'].decode('utf-8').encode('gbk')
            email = request.form['email'].encode('utf-8')

            parameters = [country,province, city, organ, depart, name, email]
            generatedevicekey = initial.CGenerateDeviceCert(parameters)
            status = generatedevicekey.SendAndReceive()
            if status == 0:
                flag = Flag.query.first()
                flag.createkeyflag = 1             
                db.session.add(flag)
                db.session.commit()
            return str(status)                     

    
    @app.route('/initial2/leadmachinecert', methods=['POST'])
    def leadmachine():
        exportcertresp = initial.ExportCert()
        status = exportcertresp.SendAndRecieve()
        if status == 0:
            flag = Flag.query.first()
            flag.exportlmcertflag = 1
            db.session.add(flag)
            db.session.commit()            
            return os.path.join(app.config['CERTIFICATE_FOLDER'],'premachine.tar.gz')
        return str(status)

    @app.route('/initial3/restartleadmachine',methods=['POST'])
    def restartlm():
        restart = initial.CRestartMachine()
        status = restart.SendAndReceive()
        if status == 0:
            flag = Flag.query.first()
            flag.restartflag = 1
            db.session.add(flag)
            db.session.commit()            
        return str(status)

    @app.route('/initial3', methods=['GET'])
    def configurelm():
        if session.get('admin') == 0:
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            lmipaddress = ['','','','']
            lmipmask = ['','','','']        
            querypredeviceip = initial.QueryPredeviceIP()
            status,ip,ipmask = querypredeviceip.SendAndReceive()
            if status == 0:
                lmipaddress = ip
                lmipmask = ipmask
            db.session.close()
            return render_template('initial3.html', lmipaddress = lmipaddress, count= count, lmipmask=lmipmask)
        else:
            return redirect('/setup') 

    @app.route('/initial3/setip', methods=['POST'])
    def setlmip():
        ipaddr1 = (request.form['ip1']).encode('utf-8')
        ipaddr2 = (request.form['ip2']).encode('utf-8')
        ipaddr3 = (request.form['ip3']).encode('utf-8')        
        ipaddr4 = (request.form['ip4']).encode('utf-8')
        ipaddr5 = (request.form['ip5']).encode('utf-8')
        ipmask1 = (request.form['ipmask1']).encode('utf-8')
        ipmask2 = (request.form['ipmask2']).encode('utf-8')
        ipmask3 = (request.form['ipmask3']).encode('utf-8')
        ipmask4 = (request.form['ipmask4']).encode('utf-8')
        ipmask5 = (request.form['ipmask5']).encode('utf-8')
        legal1 = check_ip(ipaddr1)
        legal2 = check_ip(ipaddr2)
        legal3 = check_ip(ipaddr3)
        legal4 = check_ip(ipaddr4)
        legal5 = check_ip(ipaddr5)
        legal6 = check_ip(ipmask1)
        legal7 = check_ip(ipmask2)
        legal8 = check_ip(ipmask3)
        legal9 = check_ip(ipmask4)
        legal10 = check_ip(ipmask5)
        if legal1 & legal2 & legal3 & legal4 & legal5 & legal6 & legal7 & legal8 & legal9 & legal10 == 0:
            return "-3"
        else:
            ip1 = struct.unpack('!L',socket.inet_aton(ipaddr1))[0]
            mask1 = struct.unpack('!L',socket.inet_aton(ipmask1))[0]
            ip2 = struct.unpack('!L',socket.inet_aton(ipaddr2))[0]
            mask2 = struct.unpack('!L',socket.inet_aton(ipmask1))[0]
            ip3 = struct.unpack('!L',socket.inet_aton(ipaddr3))[0]
            mask3 = struct.unpack('!L',socket.inet_aton(ipmask1))[0]
            ip4 = struct.unpack('!L',socket.inet_aton(ipaddr4))[0]
            mask4 = struct.unpack('!L',socket.inet_aton(ipmask1))[0]
            ip5 = struct.unpack('!L',socket.inet_aton(ipaddr5))[0]
            mask5 = struct.unpack('!L',socket.inet_aton(ipmask1))[0]
            re1 = ip1 & mask1
            re2 = ip2 & mask2
            re3 = ip3 & mask3
            re4 = ip4 & mask4
            re5 = ip5 & mask5
            li = [re1,re2,re3,re4,re5]
            compare = len(list(set(li)))
            print 'result = ',compare
            if compare != 5:
                return "-4"
            else:
                parameter = [ipaddr1,ipmask1, ipaddr2,ipmask2, ipaddr3,ipmask3, ipaddr4,ipmask4,ipaddr5,ipmask5]
                configpredeviceip = initial.ConfigPredeviceIP(parameter)
                # print parameter
                status = configpredeviceip.SendAndReceive()
                if status == 0:
                    leadmachine = LeadMachine.query.first()
                    if leadmachine == None:
                        lmip = ipaddr5
                        outtime = 3
                        resendtime = 1
                        newrecord = LeadMachine(lmip,outtime,resendtime)            
                        db.session.add(newrecord)
                        db.session.commit()
                    else:
                        leadmachine.lmip = ipaddr5
                        db.session.add(leadmachine)
                        db.session.commit()                        

                    # if lmip != ipaddr5:
                    #     newrecord = LeadMachine(ipaddr5)            
                    #     db.session.add(newrecord)
                    #     db.session.commit()
                    from CTFd import Transport
                    Transport.FrontendprocessorIP = ipaddr5
                    flag = Flag.query.first()
                    flag.configIPflag = 1
                    db.session.add(flag)
                    db.session.commit()
                    rank = "重要"
                    now = int(time.time())
                    name = session['username']
                    style = "LOG_NOTICE"
                    content = "设置IP"
                    log = Terminallogs(rank,now,name,style,content)
                    db.session.add(log)
                    db.session.commit()
                    db.session.close()        
                return str(status)
            # return "0"

    @app.route('/initial3/querylmip',methods=['POST'])
    def querylmip():
        querypredeviceip = initial.QueryPredeviceIP()
        status,ip,ipmask = querypredeviceip.SendAndReceive()
        ## print ip
        return str(status)

    @app.route('/initial4/setroute', methods=['POST'])
    def setlmroute():
        route = int(request.form['style'])
        IP = (request.form['rip']).encode('utf-8')
        mask = (request.form['mask']).encode('utf-8')
        gateway = (request.form['gateway']).encode('utf-8')
        interface = int(request.form['interface'])
        legal1 = check_ip(IP)
        legal2 = check_ip(mask)
        legal3 = check_ip(gateway)
        if legal1 & legal2 & legal3 == 0:
            return "-3"
        else:
            if route == 0:
                ip1 = struct.unpack('!L',socket.inet_aton(IP))[0]
                mask1 = struct.unpack('!L',socket.inet_aton(mask))[0]
                ip = ip1 & mask1
                rip = socket.inet_ntoa(struct.pack('I',socket.htonl(ip)))
            else:
                rip = IP
            operation = 1
            parameters = [operation, route, rip, mask, gateway,interface]
            configpredeviceroute = initial.ConfigPredeviceRoute(parameters)
            status = configpredeviceroute.SendAndReceive()
            if status == 0:
                querypredeviceroute = initial.QueryPredeviceRoute()
                flag = Flag.query.first()
                flag.configrouteflag = 1
                db.session.add(flag)
                db.session.commit()
                rank = "重要"
                now = int(time.time())
                name = session['username']
                style = "LOG_NOTICE"
                content = "设置路由！"
                log = Terminallogs(rank,now,name,style,content)
                db.session.add(log)
                db.session.commit()
                db.session.close() 
            return str(status)

    @app.route('/initial4', methods=['GET'])
    def querylm():
        if session.get('admin') == 0:     
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            querypredeviceroute = initial.QueryPredeviceRoute()
            status = querypredeviceroute.SendAndReceive()
            if status == 0:
                lmroute = LMRoute.query.all()
                routecount = len(lmroute)
                db.session.close()
                return render_template('initial4.html', lmroutes = lmroute, count = count ,routecount=routecount)
            else:
                lmroute = LMRoute.query.all()
                routecount = len(lmroute)
                db.session.close()
                return render_template('initial4.html',lmroutes = lmroute, count = count, routecount=routecount)
        else:
            return redirect('/setup')

    @app.route('/initial5',methods = ['GET'])
    def intial5():
        if session.get('admin') == 0:        
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            db.session.close()
            return render_template('initial5.html',count = count)
        else:
            return redirect('/setup')
    
    @app.route('/initial6',methods = ['GET'])
    def intial6():
        if session.get('admin') == 0:    
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            db.session.close()
            return render_template('initial6.html',count = count)
        else:
            return redirect('/setup')

    @app.route('/initial6/uploadcert/ca',methods = ['GET','POST'])
    def uploadcacert():

        files = request.files.getlist('files[]')            
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                if len(filename) <= 0:
                    continue
                filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                f.save(filepath)
                cert_type_code = 0            
                cerstyle = int(request.form['cerstyle'])
                try:
                    readonly = int(request.form['readonly'])
                except:
                    readonly = 0
                cert_format = int(request.form['cert_format']) 
                cert_type = (cerstyle *16) + (readonly * 8) + cert_type_code
                if cerstyle == 1:
                    filename = 'ecc_RA_ROOT.der'
                else:
                    filename = 'RA_ROOT.der'
                certfile = open(filepath, 'r')
                data = certfile.read()
                certfile.close()

                parameters = [cert_type,"0.0.0.0",cert_format, len(data), data]
                importcert = initial.CImportCert(parameters)
                status = importcert.SendAndReceive()
                if status == 0:
                    basepath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    Certificates = DLeadMachineCert.query.filter_by(certname=filename).first()
                    attachmentpath = os.path.join(basepath,filepath)
                    if Certificates == None:
                        newrecord = DLeadMachineCert(filename,attachmentpath)
                        db.session.add(newrecord)
                    else:
                        pass
                    cert = UploadCertificates.query.filter_by(certname=filename).first()
                    if(cert == None):
                        cert = UploadCertificates(filename)
                        db.session.add(cert) 
                    flag = Flag.query.first()
                    flag.importCAflag = 1
                    db.session.add(flag)
                    db.session.commit()
                AlertInfo = SwitchErrorCode(status)
                flag = Flag.query.first()
                count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                db.session.close()
                return render_template('initial5.html',count = count, AlertInfo=AlertInfo)
            else:
                flag = Flag.query.first()
                count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                db.session.close()
                return render_template('initial5.html',count = count, AlertInfo="上传证书格式不正确")

    @app.route('/initial7',methods = ['GET'])
    def intial7():
        if session.get('admin') == 0:    
            systemcertflies = []
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            return render_template('initial7.html', systemcertflies = systemcertflies, count = count)  
        else:
            return redirect('/setup')

    @app.route('/initial7/uploadcert/management',methods = ['GET','POST'])
    def uploadcert_management():
        files = request.files.getlist('files[]')         
        for f in files:
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                if len(filename) <= 0:
                    continue
                filepath = os.path.join(app.config['CERTIFICATE_FOLDER'], filename)
                f.save(filepath)

                cert_type_code = 1            
                cerstyle = int(request.form['cerstyle'])
                ##print 'cerstyle = ',cerstyle
                try:
                    readonly = int(request.form['readonly'])
                except:
                    readonly = 0
                cert_format = int(request.form['cert_format']) 
                if cerstyle == 1:
                    filename = 'ecc_DMS.der'
                else:
                    filename = 'DMS.der'
                cert_type = (cerstyle *16) + (readonly * 8) + cert_type_code
                certfile = open(filepath, 'r')
                data = certfile.read()
                certfile.close()
                parameters = [cert_type,"0.0.0.0", cert_format, len(data), data]
                ##print parameters
                importcert = initial.CImportCert(parameters)
                status = importcert.SendAndReceive()
                if status == 0:
                    basepath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    Certificates = DLeadMachineCert.query.filter_by(certname=filename).first()
                    attachmentpath = os.path.join(basepath,filepath)
                    if Certificates == None:
                        newrecord = DLeadMachineCert(filename,attachmentpath)
                        db.session.add(newrecord)
                    else:
                        pass
                    cert = UploadCertificates.query.filter_by(certname=filename).first()
                    if(cert == None):
                        cert = UploadCertificates(filename)
                        db.session.add(cert) 
                    flag = Flag.query.first()
                    flag.importsyscertflag = 1
                    db.session.add(flag)                
                    db.session.commit()        
                AlertInfo = SwitchErrorCode(status)
                flag = Flag.query.first()
                count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                db.session.close()
                return render_template('initial6.html',count = count, AlertInfo=AlertInfo)
            else:
                flag = Flag.query.first()
                count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                db.session.close()
                return render_template('initial6.html',count = count, AlertInfo="上传证书格式不正确")

    
    @app.route('/initial8',methods = ['GET'])
    def intial8():
        if session.get('admin') == 0:    
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            return render_template('initial8.html' , count = count)
        else:
            return redirect('/setup')   
    
    @app.route('/initial8/initialusbkey',methods =['POST'])
    def initialusbkey():
        status = ukey.m_ukey_prepare()
        if status != 0:
            return str(status)
        else:
            name = request.form['name'].encode('utf-8')
            epassword1 = request.form['password1']
            epassword2 = request.form['password2']
            password1 = base64.decodestring(epassword1)
            password2 = base64.decodestring(epassword2)
            country = 'CN'
            province = request.form['province'].decode('utf-8').encode('gbk')
            city = request.form['city'].decode('utf-8').encode('gbk')
            organ = 'GDD'
            depart = 'GDD'
            email = request.form['email'].encode('utf-8')
            if password1 != password2:
               return "3"
            else:
                status2 = ukey.m_ukey_init(name,password1)
                parameters = [country,province,city,organ,depart,name,email,status2['pk_ptr'],status2['id_ptr']]
                print parameters
                initialusbkey = initial.InitialUkey(parameters)
                Status = initialusbkey.SendAndReceive()
                if Status == 0:
                    enpassword = base64.encodestring(password1)
                    sql1 = "delete from users"
                    DeleteData(sql1)
                    style= 0
                    admin = 1
                    losesign = True
                    ukeyid = status2['id_ptr'].split('\x00')[0]
                    ukeycert = ukeyid + '.pem'
                    pk = ""
                    user = Users(name, admin, enpassword, ukeyid, ukeycert, style, pk, losesign)
                    db.session.add(user)
                    db.session.commit()
                    flag = Flag.query.order_by(Flag.id).first()
                    flag.initialUSBKeyflag = 1
                    db.session.add(flag)
                    db.session.commit()
                    return os.path.join(app.config['CERTIFICATE_FOLDER'],ukeyid + '.pem')
                return str(Status)                        
        

    @app.route('/initial8/exportukeycertfile',methods=['POST'])
    def exportkeycert():
        files = request.files.getlist('files[]')           
        for f in files:
            if f and allowed_file(f.filename):
                filen = secure_filename(f.filename)
                user = Users.query.first()
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
                flag = Flag.query.first()
                flag.importUSBKeyflag = 1
                db.session.add(flag)
                db.session.commit()
                count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                db.session.close()
                return render_template('initial8.html' , count = count ,AlertInfo="导入成功！")
            else:
                flag = Flag.query.first()
                count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
                db.session.close()
                return render_template('initial8.html',count = count, AlertInfo="上传证书格式不正确")

    @app.route('/restart')
    def restart():
        if authed():
            session.clear()
        return redirect('/home')

    @app.route('/reinitialize',methods=['POST'])
    def re_initialize():
        adminpassword = app.config['ADMINPASSWORD']
        epassword = request.form['epassword']
        password = base64.decodestring(epassword)
        if bcrypt_sha256.verify(password, adminpassword):
            flag = Flag.query.first()
            flag.addlmflag=0
            flag.createkeyflag=0
            flag.exportlmcertflag=0
            flag.configIPflag=0
            flag.restartflag=0
            flag.configrouteflag=0
            flag.importCAflag=0
            flag.importsyscertflag=0
            flag.initialUSBKeyflag=0
            flag.importUSBKeyflag=0
            db.session.add(flag)
            db.session.commit()
            sql2 = "truncate table terminallogs"
            DeleteData(sql2)
            sql3 = "delete from users"
            DeleteData(sql3)
            sql4 = "truncate table cipermachine"
            DeleteData(sql4)
            sql5 = "truncate table tree"
            DeleteData(sql5)
            sql6 = "truncate table lead_machine"
            DeleteData(sql6)
            sql7 = "truncate table equipments_status"
            DeleteData(sql7)
            sql8 = "truncate table prinvate_equipment_common_info"
            DeleteData(sql8)
            session.clear()

            dirPath = app.config['CERTIFICATE_FOLDER']
            if not os.path.isdir(dirPath):
                return
            files = os.listdir(dirPath)
            try:
                for file in files:
                    filePath = os.path.join(dirPath, file)
                    if os.path.isfile(filePath):
                        os.remove(filePath)
                    elif os.path.isdir(filePath):
                        removeDir(filePath)
                #os.rmdir(dirPath)
                #os.mkdir(dirPath)
            except Exception, e:
                print e

            return "1"
        else:
            return "9"

    # Static HTML files
    @app.route('/',methods=['GET'])
    def root():
        flag = Flag.query.first()
        if flag == None:
            record = Flag()
            db.session.add(record)
            db.session.commit()
            flag = Flag.query.first()
        count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
        if count == 10:
            return render_template('base.html')
        else:
            return render_template('home.html')

    @app.route('/<template>')
    def static_html(template):
        try:
            flag = Flag.query.first()
            count = flag.addlmflag + flag.createkeyflag +flag.exportlmcertflag +flag.restartflag +flag.configIPflag +flag.configrouteflag +flag.importCAflag +flag.importsyscertflag+flag.initialUSBKeyflag +flag.importUSBKeyflag
            if template == 'base':
                if count == 10:
                    return render_template('base.html')
                else:
                    return redirect('/')
            else:
                return render_template('%s.html' % template)
        except TemplateNotFound:
            abort(404)


