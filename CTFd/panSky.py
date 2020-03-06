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
    return good_id + hashlib.md5(url + str(time.time())).hexdigest()


def get_float(src):
    result = 0
    try:
        result = float(src)
    except:
        pass
    return result


def main_result(request, alert_info=None):
    page = request.args.get('page', 1, type=int)
    pagination = SkuProxyInfo.query.order_by(SkuProxyInfo.good_id, SkuProxyInfo.sku_id).paginate(page,
                                                                                                 per_page=PER_PAGE_COUNT,
                                                                                                 error_out=False)
    goods = pagination.items
    total_count = db.session.query(db.func.count(SkuProxyInfo.proxy_id)).first()[0]
    for good in goods:
        good_base_info = GoodBaseInfo.query.filter_by(good_id=good.good_id).first()
        good_sku_info = GoodSkuInfo.query.filter_by(good_id=good.good_id, sku_id=good.sku_id).first()
        good.set_parent_info(good_base_info, good_sku_info)
    viewfunc = ".main_page"
    return render_template('main.html', viewfunc=viewfunc, pagination=pagination, goods=goods, lm_total=total_count,
                           AlertInfo=alert_info)


def add_test_data():
    good_id = "612947314674"
    good = GoodBaseInfo(good_id, "家务/地板清洁", "吸尘器", "简介", "/static/img/green.png")
    db.session.add(good)
    for i in range(5):
        _sku_url = "https://detail.tmall.com/item.htm?id=612947314674"
        sku_id = create_id(good_id, _sku_url + str(i))
        sku = GoodSkuInfo(good_id, sku_id, _sku_url, 8.8)
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
                                  6.6)
            db.session.add(record)
    db.session.commit()


def set_sku_base_info(sku_info):
    good_base_info = GoodBaseInfo.query.filter_by(good_id=sku_info.good_id).first()
    good_sku_info = GoodSkuInfo.query.filter_by(good_id=sku_info.good_id, sku_id=sku_info.sku_id).first()
    sku_info.set_parent_info(good_base_info, good_sku_info)


def init_views(app):
    @app.route('/main', methods=['GET', 'POST'])
    def main_page():
        page = request.args.get('page', 1, type=int)
        pagination = SkuProxyInfo.query.order_by(SkuProxyInfo.good_id, SkuProxyInfo.sku_id).paginate(page,
                                                                                                     per_page=PER_PAGE_COUNT,
                                                                                                     error_out=False)
        goods = pagination.items
        total_count = db.session.query(db.func.count(SkuProxyInfo.proxy_id)).first()[0]
        for good in goods:
            good_base_info = GoodBaseInfo.query.filter_by(good_id=good.good_id).first()
            good_sku_info = GoodSkuInfo.query.filter_by(good_id=good.good_id, sku_id=good.sku_id).first()
            good.set_parent_info(good_base_info, good_sku_info)
        viewfunc = ".main_page"
        return render_template('main.html', viewfunc=viewfunc, pagination=pagination, goods=goods, lm_total=total_count)

    @app.route('/search', methods=['GET', 'POST'])
    def search():
        if request.method == 'GET':
            return redirect("/main")
        page = request.args.get('page', 1, type=int)
        good_id = get_id(str(request.form['search_good_id']))
        good_title = request.form['search_good_title']
        good_proxy_id = get_id(str(request.form['search_proxy_id']))
        if good_id != "" and good_proxy_id != "":
            query = SkuProxyInfo.query.filter_by(good_id=good_id, good_proxy_id=good_proxy_id)
            pagination = query.paginate(page, per_page=PER_PAGE_COUNT, error_out=False)
            goods = pagination.items
            total_count = len(query.all())
            for good in goods:
                set_sku_base_info(good)
        elif good_id != "":
            query = SkuProxyInfo.query.filter_by(good_id=good_id).order_by(SkuProxyInfo.sku_id)
            pagination = query.paginate(page, per_page=PER_PAGE_COUNT, error_out=False)
            goods = pagination.items
            total_count = len(query.all())
            for good in goods:
                set_sku_base_info(good)
        elif good_proxy_id != "":
            query = SkuProxyInfo.query.filter_by(good_id=good_id, good_proxy_id=good_proxy_id)
            pagination = query.paginate(page, per_page=PER_PAGE_COUNT, error_out=False)
            goods = pagination.items
            total_count = len(query.all())
            for good in goods:
                set_sku_base_info(good)
        elif good_title != "":
            goods = GoodBaseInfo.query.filter(GoodBaseInfo.good_title.like("%" + good_title + '%')).all()
            ids = []
            for good in goods:
                ids.append(good.good_id)
            query = SkuProxyInfo.query.filter(SkuProxyInfo.good_id.in_(ids)).order_by(SkuProxyInfo.good_id,
                                                                                      SkuProxyInfo.sku_id)
            pagination = query.paginate(page, per_page=PER_PAGE_COUNT, error_out=False)
            goods = pagination.items
            for good in goods:
                set_sku_base_info(good)
            total_count = len(query.all())
        else:
            return redirect('/main')
        viewfunc = ".search"
        return render_template('main.html', viewfunc=viewfunc, pagination=pagination, goods=goods, lm_total=total_count,
                               search_good_id=good_id, search_good_title=good_title, search_proxy_id=good_proxy_id)

    @app.route('/love', methods=['GET', 'POST'])
    def main_test():
        return render_template('maintest.html')

    @app.route('/forever', methods=['GET', 'POST'])
    def main_forever():
        return render_template('forever.html')

    @app.route('/good/new', methods=['POST'])
    def add_good():
        good_id = request.form['good_id']
        record = GoodBaseInfo.query.filter_by(good_id=good_id).first()
        if record is not None:
            return main_result(request, "该商品已存在！")
        good_name = request.form['good_name']
        description = request.form['description']
        category = request.form['category']
        sku_url = request.form['sku']
        sku_id = create_id(good_id, sku_url)
        sku_description = request.form["sku_description"]
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
        day_limit = get_float(request.form["day_limit"])
        activity_limit = get_float(request.form["activity_limit"])
        proxy_shop = request.form["proxy_shop"]
        upload_file = request.files['file']
        image_path = ""
        if upload_file and allowed_file(upload_file.filename):
            filename = good_id + "." + get_file_suffix(upload_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            upload_file.save(image_path)
        base_info = GoodBaseInfo(good_id, category, good_name, description, image_path, has_video, coupon, prize)
        db.session.add(base_info)
        sku_info = GoodSkuInfo(good_id, sku_id, sku_url, price, sku_description)
        db.session.add(sku_info)
        proxy_info = SkuProxyInfo(good_id, sku_id, proxy_url, express, postage, address, produce_address, cost,
                                  qualification, day_limit, activity_limit, extra, proxy_shop)
        db.session.add(proxy_info)
        db.session.commit()
        db.session.close()
        return redirect('/main')

    @app.route('/goods/delete', methods=['POST'])
    def delete_goods():
        goods_ids = request.form['choose_goods_ids'].encode('utf-8').strip(',').split(',')
        for id in goods_ids:
            GoodBaseInfo.query.filter_by(good_id=id).delete()
            GoodSkuInfo.query.filter_by(good_id=id).delete()
            SkuProxyInfo.query.filter_by(good_id=id).delete()
        db.session.commit()
        db.session.close()
        return "0"

    @app.route('/goods/edit', methods=["POST"])
    def edit_goods():
        good_id = request.form['edit_good_id']
        base_info = GoodBaseInfo.query.filter_by(good_id=good_id).first()
        if base_info is None:
            return "0"
        good_name = request.form['edit_good_name']
        description = request.form['edit_description']
        category = request.form['edit_category']
        coupon = get_float(request.form['edit_coupon'])
        prize = get_float(request.form['edit_prize'])
        has_video = int(request.form["edit_has_video"])
        sku_url = request.form['edit_sku_url']
        sku_id = request.form['edit_sku_id']
        sku_description = request.form["edit_sku_description"]
        price = get_float(request.form['edit_price'])
        proxy_id = int(request.form["edit_proxy_id"])
        proxy_url = request.form['edit_proxy_url']
        cost = get_float(request.form['edit_cost'])
        express = request.form['edit_express']
        postage = get_float(request.form['edit_postage'])
        address = request.form['edit_address']
        produce_address = request.form['edit_produce']
        qualification = request.form['edit_qualification']
        extra = request.form['edit_extra']
        day_limit = get_float(request.form["edit_day_limit"])
        activity_limit = get_float(request.form["edit_activity_limit"])
        proxy_shop = request.form["edit_proxy_shop"]


        sku_info = GoodSkuInfo.query.filter_by(good_id=good_id, sku_id=sku_id).first()
        if sku_info is None:
            return "0"
        proxy_info = SkuProxyInfo.query.filter_by(proxy_id=proxy_id).first()
        if proxy_info is None:
            return "0"
        base_info.good_title = good_name
        base_info.good_description = description
        base_info.coupon = coupon
        base_info.good_prize = prize
        base_info.category = category
        base_info.good_has_video = has_video

        sku_info.sku_url = sku_url
        sku_info.sku_price = price
        sku_info.sku_description = sku_description

        proxy_info.good_proxy_url = proxy_url
        proxy_info.good_cost = cost
        proxy_info.good_express = express
        proxy_info.postage_address = address
        proxy_info.good_postage = postage
        proxy_info.produce_address = produce_address
        proxy_info.qualification = qualification
        proxy_info.good_extra = extra
        proxy_info.day_limit = day_limit
        proxy_info.activity_limit = activity_limit
        proxy_info.proxy_shop = proxy_shop
        # upload_file = request.files['file']
        # if upload_file and allowed_file(upload_file.filename):
        #     filename = good_id + "." + get_file_suffix(upload_file.filename)
        #     image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        #     if os.path.exists(image_path):
        #         os.remove(image_path)
        #     upload_file.save(image_path)
        #     base_info.good_image_url = image_path
        db.session.add(base_info)
        db.session.add(sku_info)
        db.session.add(proxy_info)
        db.session.commit()
        db.session.close()
        return "1"

    @app.route('/goods/add/proxy', methods=["POST"])
    def add_proxy():
        good_id = request.form['edit_good_id']
        sku_id = request.form['edit_sku_id']
        base_info = GoodBaseInfo.query.filter_by(good_id=good_id).first()
        if base_info is None:
            return "0"

        sku_info = GoodSkuInfo.query.filter_by(good_id=good_id, sku_id=sku_id).first()
        if sku_info is None:
            return "0"

        proxy_url = request.form['edit_proxy_url']
        cost = get_float(request.form['edit_cost'])
        express = request.form['edit_express']
        postage = get_float(request.form['edit_postage'])
        address = request.form['edit_address']
        produce_address = request.form['edit_produce']
        qualification = request.form['edit_qualification']
        extra = request.form['edit_extra']
        day_limit = get_float(request.form["edit_day_limit"])
        activity_limit = get_float(request.form["edit_activity_limit"])
        proxy_shop = request.form["edit_proxy_shop"]
        proxy_info = SkuProxyInfo(good_id, sku_id, proxy_url, express, postage, address, produce_address, cost,
                                  qualification, day_limit, activity_limit, extra, proxy_shop)
        db.session.add(sku_info)
        db.session.add(proxy_info)
        db.session.commit()
        db.session.close()
        return "1"

    @app.route('/goods/add/sku', methods=["POST"])
    def add_sku():
        good_id = request.form['edit_good_id']
        base_info = GoodBaseInfo.query.filter_by(good_id=good_id).first()
        if base_info is None:
            return "0"

        sku_url = request.form['edit_sku_url']
        sku_id = create_id(good_id, sku_url)
        price = get_float(request.form['edit_price'])
        sku_description = request.form["edit_sku_description"]
        proxy_url = request.form['edit_proxy_url']
        cost = get_float(request.form['edit_cost'])
        express = request.form['edit_express']
        postage = get_float(request.form['edit_postage'])
        address = request.form['edit_address']
        produce_address = request.form['edit_produce']
        qualification = request.form['edit_qualification']
        extra = request.form['edit_extra']
        day_limit = get_float(request.form["edit_day_limit"])
        activity_limit = get_float(request.form["edit_activity_limit"])
        proxy_shop = request.form["edit_proxy_shop"]
        sku_info = GoodSkuInfo(good_id, sku_id, sku_url, price, sku_description)
        proxy_info = SkuProxyInfo(good_id, sku_id, proxy_url, express, postage, address, produce_address, cost,
                                  qualification, day_limit, activity_limit, extra, proxy_shop)
        db.session.add(sku_info)
        db.session.add(proxy_info)
        db.session.commit()
        db.session.close()
        return "1"

    @app.route('/goods/delete/proxy', methods=["POST"])
    def delete_proxy():
        good_id = request.form['delete_proxy_good_id']
        sku_id = request.form['delete_proxy_sku_id']
        proxy_id = request.form['delete_proxy_id']
        proxy_infos = SkuProxyInfo.query.filter_by(good_id=good_id, sku_id=sku_id).all()
        SkuProxyInfo.query.filter_by(good_id=good_id, sku_id=sku_id, proxy_id=proxy_id).delete()
        if len(proxy_infos) == 1:
            db.session.add(SkuProxyInfo(good_id, sku_id))
        db.session.commit()
        db.session.close()
        return "0"

    @app.route('/goods/delete/sku', methods=["POST"])
    def delete_sku():
        good_id = request.form['delete_sku_good_id']
        sku_id = request.form['delete_sku_id']
        sku_infos = GoodSkuInfo.query.filter_by(good_id=good_id).all()
        GoodSkuInfo.query.filter_by(good_id=good_id, sku_id=sku_id).delete()
        SkuProxyInfo.query.filter_by(good_id=good_id, sku_id=sku_id).delete()
        if len(sku_infos) == 1:
            db.session.add(GoodSkuInfo(good_id, sku_id))
            db.session.add(SkuProxyInfo(good_id, sku_id))
        db.session.commit()
        db.session.close()
        return "0"
