# coding=utf-8
from flask import render_template, request, redirect, abort, jsonify, url_for, session, flash, send_from_directory
from CTFd.utils import sha512, authed, judge_result, check_ip, check_mac, allowed_file, AddCommonStatus, AddPrivateStatus
from CTFd import initial, ukey, Transport
from CTFd.models import db, Users, SysIPAddress, SystemRoutes, LeadMachine, Cipermachine, Terminallogs, LeadMachinelogs, EquipmentsStatus, Certificates, CertDetail, ChannelStatus, ChannelNumber,DSecurityStrategy,Tree,DRouteTable,DPrivateCertInfo,LMRoute,DPrivateChannelInfo,DStandarCertificate,UploadCertificates,Good
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

def init_views(app):
    @app.route('/main', methods=['GET', 'POST'])
    def mainPage():
        page = request.args.get('page',1, type=int)
        pagination=Good.query.paginate(page,per_page=15,error_out=False)
        goods = pagination.items
        total_count = db.session.query(db.func.count(Good.id)).first()[0]
        if total_count == 0:
            for i in range(20):
                record = Good()
                db.session.add(record)
        db.session.commit()
        viewfunc = ".user2"
        return render_template('main.html',viewfunc=viewfunc,pagination=pagination,goods=goods, lm_total=total_count)