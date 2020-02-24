#!/usr/bin/env python
# coding=utf-8

from CTFd.models import db, Users, EquipmentsStatus, Cipermachine, DPrivateEquipmentCommonInfo
from CTFd import mail

from urlparse import urlparse, urljoin
from functools import wraps
from flask import current_app as app, g, request, redirect, url_for, session,render_template
from flask.ext.mail import Message
from socket import inet_aton, inet_ntoa
from struct import unpack, pack

import time
import datetime
import hashlib
import json
import sys
import re

ALLOWED_EXTENSIONS = set(['der'])


def init_utils(app):
    app.jinja_env.filters['long2ip'] = long2ip

def authed():
    return bool(session.get('uid', False))

def is_admin():
    if authed():
        return session['admin']
    else:
        return False

def admins_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin', 0) == 0:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def long2ip(ip_int):
    return inet_ntoa(pack('!I', ip_int))

def ip2long(ip):
    return unpack('!I', inet_aton(ip))[0]

def sha512(string):
    return hashlib.sha512(string).hexdigest()

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1] in ALLOWED_EXTENSIONS

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def judge_result(result):
    errors = []
    if result == -2:
        errors.append("操作超时！")
    elif result == -1:
        errors.append("操作ukey错误!")
    elif result == 16:
        errors.append("ukey未插入！")
    elif result == 32:
        errors.append("ukey未初始化！")
    elif result == 48:
        errors.append("ukey口令错误已达到上限（8次）！")
    elif result >64 and result < 80:
        num = result - 64
        errors.append("ukey口令错误！错误次数为：" + str(num))
    elif result == 80:
        errors.append("ukey的pin码未知,初始化失败！")
    elif result == 96:
        errors.append("获取ukey信息失败！")
    elif result == 112:
        errors.append("输入参数不合法！")
    elif result == 128:
        errors.append("输入ukey id与ukey自身的id不一致！")
    elif result == 144:
        errors.append("输入username与ukey中的username不一致！")
    elif result == 160:
        errors.append("ukey认证失败！")
    else:
        errors.append("操作异常!")
    return errors

def check_ip(ip):
    pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    if re.match(pattern,ip):
        return True
    else:
        return False

def check_mac(mac):  
    if re.match(r"^\s*([0-9a-fA-F]{2,2}:){5,5}[0-9a-fA-F]{2,2}\s*$", mac): return True  
    return False  


def whichEncode(text):
    if isinstance(text,unicode):
        return 0
    try:
        text.decode("utf-8")
        return 1
    except:
        pass
    try:
        text.decode("gbk")
        return 2
    except:
        pass


def AddCommonStatus(ip):
    machine = Cipermachine.query.filter_by(ip=ip).first()
    status = 1
    workmodel = None
    sign = None
    restain = None
    encrypt = None
    decrypt = None
    errorencrypt = None
    errordecrypt = None
    send = None
    receive = None
    errorreceive = None
    status = EquipmentsStatus(machine.id,status,workmodel,sign,restain,encrypt,decrypt,errorencrypt,errordecrypt,send,receive,errorreceive)
    db.session.add(status)
    db.session.commit()
    return 0

def AddPrivateStatus(ip):
    machine = Cipermachine.query.filter_by(ip=ip).first()
    work_status = 1
    status = DPrivateEquipmentCommonInfo(machine.id,{"work_status":work_status})
    db.session.add(status)
    db.session.commit()
    return 0

