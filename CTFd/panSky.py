# coding=utf-8
from flask import render_template, request, redirect, abort, jsonify, url_for, session, flash, send_from_directory
from CTFd.utils import authed, judge_result, allowed_file, get_file_suffix
from CTFd.models import db, GoodBaseInfo, GoodSkuInfo, SkuProxyInfo, get_id
from flask import current_app as app
from werkzeug.utils import secure_filename

import time
import hashlib
import re
import os
import sys
authority = app.config['MYSQL_USER']
password = app.config['MYSQL_PASSWORD']
name = app.config['DATEBASE_NAME']
reload(sys)
sys.setdefaultencoding('utf-8')
PER_PAGE_COUNT = 20
def create_id(good_id, url):
    return good_id + hashlib.md5(url +  str(time.time())).hexdigest()

def get_float(src):
    result = 0
    try:
        result = float(src)
    except:
        pass
    return result
def main_result(request, alert_info = None):
    page = request.args.get('page', 1, type=int)
    pagination = SkuProxyInfo.query.order_by(SkuProxyInfo.good_id).paginate(page, per_page=PER_PAGE_COUNT, error_out=False)
    goods = pagination.items
    total_count = db.session.query(db.func.count(SkuProxyInfo.proxy_id)).first()[0]
    for good in goods:
        good_base_info = GoodBaseInfo.query.filter_by(good_id=good.good_id).first()
        good_sku_info = GoodSkuInfo.query.filter_by(good_id=good.good_id, sku_id=good.sku_id).first()
        good.set_parent_info(good_base_info, good_sku_info)
    viewfunc = ".main_page"
    return render_template('main.html', viewfunc=viewfunc, pagination=pagination, goods=goods, lm_total=total_count, AlertInfo = alert_info)
def add_test_data():
    good_id = "612947314674"
    good = GoodBaseInfo(good_id, "吸尘器", "简介", "/static/img/green.png")
    db.session.add(good)
    for i in range(5):
        _sku_url = "https://detail.tmall.com/item.htm?id=612947314674"
        sku_id = create_id(good_id, _sku_url + str(i))
        sku = GoodSkuInfo(good_id, sku_id, _sku_url, 8.8, 1.1)
        db.session.add(sku)
        for i in range(5):
            good_proxy_url = "http://mobile.yangkeduo.com/goods.html?goods_id=2823236263"
            record = SkuProxyInfo(good_id,
                                  sku_id,
                                  good_proxy_url,
                                  "韵达 顺丰",
                                  3,
                                  "安徽",
                                  "浙江",
                                  6.6,
                                  0)
            db.session.add(record)
    db.session.commit()
def init_views(app):
    @app.route('/main', methods=['GET', 'POST'])
    def main_page():
        page = request.args.get('page',1, type=int)
        pagination= SkuProxyInfo.query.order_by(SkuProxyInfo.good_id).paginate(page,per_page=PER_PAGE_COUNT,error_out=False)
        goods = pagination.items
        total_count = db.session.query(db.func.count(SkuProxyInfo.proxy_id)).first()[0]
        for good in goods:
            good_base_info = GoodBaseInfo.query.filter_by(good_id=good.good_id).first()
            good_sku_info = GoodSkuInfo.query.filter_by(good_id=good.good_id, sku_id=good.sku_id).first()
            good.set_parent_info(good_base_info, good_sku_info)
        viewfunc = ".main_page"
        return render_template('main.html',viewfunc=viewfunc,pagination=pagination,goods=goods, lm_total=total_count)
    @app.route('/search', methods=['GET', 'POST'])
    def search():
        page = request.args.get('page', 1, type=int)
        good_id = get_id(request.form['search_good_id'])
        good_title = request.form['search_good_title']
        good_proxy_id = get_id(request.form['search_proxy_id'])
        if good_id != "" and good_proxy_id != "":
            query = SkuProxyInfo.query.filter_by(good_id=good_id, good_proxy_id=good_proxy_id).paginate(page,per_page=PER_PAGE_COUNT,error_out=False)
        elif good_id != "":
            query = SkuProxyInfo.query.filter_by(good_id=good_id).paginate(page,per_page=PER_PAGE_COUNT,error_out=False)
        elif good_proxy_id != "":
            query = SkuProxyInfo.query.filter_by(good_id=good_id, good_proxy_id=good_proxy_id).paginate(page,per_page=PER_PAGE_COUNT,error_out=False)
        elif good_title != "":
            goods = GoodBaseInfo.query.filter(GoodBaseInfo.good_title.like("%" + good_title + '%')).all()
            ids = []
            for good in goods:
                ids.append(good.good_id)
            query = SkuProxyInfo.query.filter(SkuProxyInfo.good_id.in_(ids)).paginate(page,per_page=PER_PAGE_COUNT,error_out=False)
        else:
            return redirect('/main')
        pagination = query.paginate(page, per_page=PER_PAGE_COUNT,error_out=False)
        goods = pagination.items
        total_count = len(query.all())
        viewfunc = ".search"
        return render_template('main.html',viewfunc=viewfunc,pagination=pagination,goods=goods, lm_total=total_count, search_good_id=good_id, search_good_title=good_title, search_proxy_id=good_proxy_id)

    @app.route('/test', methods=['GET', 'POST'])
    def main_test():
        return render_template('maintest.html')
    @app.route('/good/new', methods=['POST'])
    def add_good():
        add_test_data()
        good_id = request.form['good_id']
        record = GoodBaseInfo.query.filter_by(good_id=good_id).first()
        if record is not None:
            return main_result(request, "该商品已存在！")
        good_name = request.form['good_name']
        description = request.form['description']
        sku_url = request.form['sku']
        sku_id = create_id(good_id, sku_url)
        price = get_float(request.form['price'])
        proxy_url = request.form['proxy_url']
        cost = get_float(request.form['cost'])
        coupon = get_float(request.form['coupon'])
        express = request.form['express']
        postage = get_float(request.form['postage'])
        address = request.form['address']
        produce_address = request.form['produce']
        prize = get_float(request.form['prize'])
        qualification = request.form['qualification']
        extra = request.form['extra']
        has_video = int(request.form["has_video"])
        upload_file = request.files['file']
        image_path = ""
        if upload_file and allowed_file(upload_file.filename):
            filename = good_id + "." + get_file_suffix(upload_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            upload_file.save(image_path)
        base_info = GoodBaseInfo(good_id, good_name, description, image_path, has_video)
        db.session.add(base_info)
        sku_info = GoodSkuInfo(good_id, sku_id, sku_url, price, coupon)
        db.session.add(sku_info)
        proxy_info = SkuProxyInfo(good_id, sku_id, proxy_url, express, postage, address, produce_address, cost,prize, qualification, extra)
        db.session.add(proxy_info)
        db.session.commit()
        db.session.close()
        return redirect('/main')
    @app.route('/goods/delete', methods=['POST'])
    def delete_goods():
        goods_ids= request.form['choose_goods_ids'].encode('utf-8').strip(',').split(',')
        for id in goods_ids:
            GoodBaseInfo.query.filter_by(good_id=id).delete()
            GoodSkuInfo.query.filter_by(good_id=id).delete()
            SkuProxyInfo.query.filter_by(good_id=id).delete()
        db.session.commit()
        db.session.close()
        return "0"


