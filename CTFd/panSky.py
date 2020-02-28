# coding=utf-8
from flask import render_template, request, redirect, abort, jsonify, url_for, session, flash, send_from_directory
from CTFd.utils import sha512, authed, judge_result, check_ip, check_mac, allowed_file, AddCommonStatus, AddPrivateStatus
from CTFd import initial, ukey, Transport
from CTFd.models import db, GoodBaseInfo, GoodSkuInfo, SkuProxyInfo
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
import MySQLdb
authority = app.config['MYSQL_USER']
password = app.config['MYSQL_PASSWORD']
name = app.config['DATEBASE_NAME']
reload(sys)
sys.setdefaultencoding('utf-8')
def create_id(good_id, url):
    return good_id + hashlib.md5(url +  str(time.time())).hexdigest()

def init_views(app):
    @app.route('/main', methods=['GET', 'POST'])
    def mainPage():
        page = request.args.get('page',1, type=int)
        pagination= SkuProxyInfo.query.order_by(SkuProxyInfo.good_id).paginate(page,per_page=20,error_out=False)
        goods = pagination.items
        total_count = db.session.query(db.func.count(SkuProxyInfo.id)).first()[0]
        for good in goods:
            good_base_info = GoodBaseInfo.query.first()
            good_sku_info = GoodSkuInfo.query.first()
            good.set_parent_info(good_base_info, good_sku_info)
        if total_count == 0:
            good_id = "6147245"
            good = GoodBaseInfo(good_id, "吸尘器", "", "/static/img/green.png")
            db.session.add(good)
            for i in range(5):
                _sku_url = "https://detail.tmall.com/item.htm?id=612947314674"
                sku_id = create_id(good_id, _sku_url + str(i))
                sku = GoodSkuInfo(good_id, sku_id, _sku_url, 8.8, 0)
                db.session.add(sku)
                for i in range(5):
                    good_proxy_url = "http://mobile.yangkeduo.com/goods.html?goods_id=2823236263"
                    record = SkuProxyInfo(good_id,
                                          sku_id,
                                          good_proxy_url,
                                          "韵达 顺丰",
                                          3,
                                          "安徽",
                                          6.6,
                                          0)
                    db.session.add(record)
        db.session.commit()
        viewfunc = ".user2"
        return render_template('main.html',viewfunc=viewfunc,pagination=pagination,goods=goods, lm_total=total_count)