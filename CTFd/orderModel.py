#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import requests
from bs4 import BeautifulSoup
import re
import json
import yaml
class PingDuoDuoGood:
    def __init__(self, _good_name="", _good_number="", _good_price="", _good_link_url=""):
        self.goods_name = _good_name
        self.goods_price = _good_price
        self.goods_number = _good_number
        self.goods_link_url = _good_link_url
    def to_string(self):
        return self.goods_name + "  " + str(self.goods_number) + "件 " + str(self.goods_price)
    def parse(self, data):
        if data is not None:
            self.goods_name = get_not_none(data, "goods_name", "")
            self.goods_number = get_not_none(data, "goods_number", 0)
            self.goods_price = get_not_none(data, "goods_price", 0)
        return self

def pares(data):
    orders = data.get("orders")
    for order in orders:
        order_info = OrderInfo()
        order_info.parse(order)
def get_not_none(data, key, default=""):
    value = data.get(key)
    return value if value is not None else default
def get_int_not_none(data, key, default = 0):
    value = data.get(key)
    return value if value is not None else default
class MallInfo:
    def __init__(self, _id = "", _mall_name = "", _mall_url = ""):
        self.id = _id
        self.mall_name = _mall_name
        self.mall_url = _mall_url
    def parse(self, data):
        if data is not None:
            self.id = get_not_none(data, "id")
            self.mall_name = get_not_none(data, "mall_name")
            self.mall_url = get_not_none(data, "mall_url")
        return self

class OrderInfo:
    def __init__(self):
        self.order_sn = ""
        self.order_status = 0
        self.pay_status = 0
        self.shipping_time = 0
        self.order_time = 0
        self.receive_time = 0
        self.expect_auto_receive_time = 0
        self.order_link_url = ""
        self.mall_info = MallInfo()
        self.express_id = ""
        self.order_goods = []
    def parse(self, data):
        self.order_sn = get_not_none(data, "order_sn")
        self.order_status = get_int_not_none(data, "order_status", 0)
        self.pay_status = get_int_not_none(data, "pay_status", 0)
        self.shipping_time = get_int_not_none(data, "shipping_time", 0)
        self.order_time = get_int_not_none(data, "order_time", 0)
        self.receive_time = get_int_not_none(data, "receive_time", 0)
        self.expect_auto_receive_time = get_int_not_none(data, "expect_auto_receive_time", 0)
        self.order_link_url = get_not_none(data, "order_link_url")
        self.mall_info = MallInfo().parse(data.get("mall"))
        self.express_id = get_not_none(data, "tracking_number")
        order_goods = data.get("order_goods")
        self.order_goods = []
        if order_goods is not None:
            for goods in order_goods:
                self.order_goods.append(PingDuoDuoGood().parse(goods))
        return self




class DetailInfo:
    @staticmethod
    def get_not_none(data, key, default=""):
        value = data.get(key)
        return value if value is not None else default
    def __init__(self, _order_id = "",
                 _pay_way="",
                 _snapshot="",
                 _buy_time="",
                 _send_type="",
                 _express="",
                 _express_id="",
                 _send_time="",
                 _goods="",
                 _mall_id= 0,
                 _mall_name="",
                 _mall_url="",
                 _receive_name="",
                 _mobile="",
                 _address=""):
        self.order_id = _order_id
        self.pay_way = _pay_way
        self.snapshot = _snapshot
        self.buy_time_str = _buy_time
        self.express = _express
        self.express_id = _express_id
        self.send_time_str = _send_time
        self.goods = _goods
        self.goods_list = []
        self.mall_id = _mall_id
        self.mall_name = _mall_name
        self.mall_url = _mall_url
        self.mobile = _mobile
        self.receive_name = _receive_name
        self.address = _address
    def parse_order_list(self, data):
        if data is None:
            return
        for keyValue in data:
            key = keyValue.get("key")
            value = keyValue.get("value")
            if "订单编号" in key:
                self.order_id = value
            elif "支付方式" in key:
                self.pay_way = value
            elif "商品快照" in key:
                self.snapshot = value
            elif "下单时间" in key:
                self.buy_time_str = value
            elif "发货时间" in key:
                self.send_time_str = value
            elif "物流公司" in key:
                self.express = value
            elif "快递单号" in key:
                self.express_id = value
    def parse_goods(self, data):
        if data is None:
            return
        self.goods_list = []
        for goods in data:
            goods_name = self.get_not_none(goods, "goodsName")
            goods_price = self.get_not_none(goods, "goodsPrice", 0)
            goods_number = self.get_not_none(goods, "goodsNumber", 0)
            goods_url = self.get_not_none(goods, "linkUrl")
            self.goods_list.append(PingDuoDuoGood(goods_name, goods_number, goods_price, goods_url).to_string())
        self.goods = "\n".join(self.goods_list)
    def parse_mall(self, data):
        if data is None:
            return
        self.mall_id = self.get_not_none(data, "id", 0)
        self.mall_name = self.get_not_none(data, "mallName")
        self.mall_url = self.get_not_none(data, "mallUrl")
    def parse_receive_info(self, data):
        self.receive_name = self.get_not_none(data, "receiveName")
        self.mobile = self.get_not_none(data, "mobile")
        address = self.get_not_none(data, "address")
        district_name = self.get_not_none(data, "districtName")
        city_name = self.get_not_none(data, "cityName")
        shipping_address = self.get_not_none(data, "shippingAddress")
        province_name = self.get_not_none(data, "provinceName")
        self.address = province_name + city_name + district_name + shipping_address + address
    def parse(self, data):
        self.parse_receive_info(data)
        self.parse_order_list(data.get("orderDescList"))
        self.parse_goods(data.get("orderGoods"))
        self.parse_mall(data.get("mall"))

class Order:
    def __init__(self, _user_id,  _order_info = OrderInfo(), _detail_info = DetailInfo()):
        self.user_id = _user_id
        self.order_info = _order_info
        self.detail_info = _detail_info