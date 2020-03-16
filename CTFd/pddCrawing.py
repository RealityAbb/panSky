#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import requests
from bs4 import BeautifulSoup
import re
import json
import yaml
from CTFd.orderModel import DetailInfo, PingDuoDuoGood, OrderInfo, Order
def byteify(input):
    if isinstance(input, dict):
        return {byteify(key): byteify(value) for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input
def set_user_agent():
    USER_AGENTS = [
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
        "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
        "Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
        "Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 80.0.3987.116Safari / 537.36"
    ]
    user_agent = random.choice(USER_AGENTS)
    return user_agent
COUNT_PER_TIMES = 10
class PinDuoDuo:
    def __init__(self, _cookie):
        self.cookies_str = _cookie
        self.cookies = {}  # 申明一个字典用于存储手动复制的cookies
        self.res_cookies_txt = ""  # 申明刚开始浏览器返回的cookies为空字符串
        self.parse_cookies()
        self.cookies_jar = self.parse_cookies()
        self.user_id = self.cookies.get("pdd_user_id")
        self.token = self.cookies.get("PDDAccessToken")
        self.order_list_url = 'http://mobile.yangkeduo.com/proxy/api/api/aristotle/order_list?pdduid=' + str(self.user_id)
        self.get_detail_url_domain = "http://mobile.yangkeduo.com/"
        self.headers = {"Origin": "http://mobile.yangkeduo.com",
                        "Upgrade-Insecure-Requests": "1",
                        "Content-Length": "185",
                        "sec-fetch-dest": "document",
                        "Content-Type": "application/json;charset=UTF-8",
                        "Accept": "application/json, text/plain, */*",
                        "AccessToken": self.token,
                        "Referer": "http://mobile.yangkeduo.com/orders.html?type=0&refer_page_name=personal&refer_page_id=10001_1584190818662_e82cxxyofe&refer_page_sn=10001&order_index=0",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": "zh-CN,zh;q=0.9,ko-KR;q=0.8,ko;q=0.7,en-US;q=0.6,en;q=0.5",
                        "Collection": "keep-alive",}
        self.get_detail_headers = {
                        "Upgrade-Insecure-Requests": "1",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                        "Referer": "http://mobile.yangkeduo.com/orders.html?type=0&refer_page_name=personal&refer_page_id=10001_1584190818662_e82cxxyofe&refer_page_sn=10001&order_index=0",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Accept-Language": "zh-CN,zh;q=0.9,ko-KR;q=0.8,ko;q=0.7,en-US;q=0.6,en;q=0.5",
                        "Collection": "keep-alive",
                        "Cache-Control": "max-age=0",
                        "User-Agent": set_user_agent()}
    # 读取mycookies.txt中的cookies
    def parse_cookies(self):
        cookies_txt = self.cookies_str.strip(';')  # 读取文本内容
        # 由于requests只保持 cookiejar 类型的cookie，而我们手动复制的cookie是字符串需先将其转为dict类型后利用requests.utils.cookiejar_from_dict转为cookiejar 类型
        # 手动复制的cookie是字符串转为字典：
        for cookie in cookies_txt.split(';'):
            name, value = cookie.strip().split('=', 1)  # 用=号分割，分割1次
            self.cookies[name] = value  # 为字典cookies添加内容
        # 将字典转为CookieJar：
        cookies_jar = requests.utils.cookiejar_from_dict(self.cookies, cookiejar=None, overwrite=True)
        ##print cookiesJar
        return cookies_jar

    def query_detail(self, session, url):
        session.headers = self.get_detail_headers
        response = session.get(url)
        soup = BeautifulSoup(response.text, "lxml")
        p = re.compile('window.rawData=(.*);')
        scripts = soup.find_all("script", {"src": False})
        tag = "window.rawData="
        for script in scripts:
            all_value = str(script)
            if all_value:
                start = all_value.find(tag)
                if start < 0:
                    continue
                end = all_value.find(";", start)
                result = all_value[len(tag) + start : end]
                js = json.loads(result, encoding="utf-8")
                js = byteify(js)
                with open('result.txt', "w") as f:
                    f.write(str(js["data"]))
                detail = DetailInfo()
                detail.parse(js["data"])
                return detail
        return None

    def query_record_list(self, session, offset):
        session.headers = self.headers
        post_data = {"timeout": 1300, "type": "all", "page": 1,
                "pay_channel_list": ["9", "30", "31", "35", "38", "52", "322", "-1"],
                "origin_host_name": "mobile.yangkeduo.com", "size": COUNT_PER_TIMES, "offset": offset}
        response = session.post(self.order_list_url, json=post_data)
        data = json.loads(response.text, encoding="utf-8")
        data = byteify(data)
        orders = data.get("orders")
        order_list = []
        for order in orders:
            order_info = OrderInfo()
            order_info.parse(order)
            order_list.append(order_info)
        return order_list
    def start(self):
        # 开启一个session会话
        session = requests.session()
        # 设置请求头信息
        # 将cookiesJar赋值给会话
        session.cookies = self.cookies_jar
        ## 请求全部订单数据
        all_order_list = []
        order_list = self.query_record_list(session, 0)
        while len(order_list) >= COUNT_PER_TIMES:
            all_order_list.extend(order_list)
            order_list = self.query_record_list(session, order_list[-1].order_sn)
        all_order_list.extend(order_list)
        result = []
        for order in all_order_list:
            order_detail_url = self.get_detail_url_domain + order.order_link_url
            detail = self.query_detail(session, order_detail_url)
            result.append(Order(self.user_id, order, detail))
        return result
if __name__ == '__main__':
    cookie = "api_uid=CiS3pV5XK+a4+gA9HAy9Ag==; _nano_fp=XpdJX5m8Xpg8npTxlT_aGkXe9DO4t3ayz8s5eVIc; ua=Mozilla%2F5.0%20(Macintosh%3B%20Intel%20Mac%20OS%20X%2010_13_6)%20AppleWebKit%2F537.36%20(KHTML%2C%20like%20Gecko)%20Chrome%2F80.0.3987.132%20Safari%2F537.36; webp=1; msec=1800000; PDDAccessToken=KIUAD4UTI3X3TR7NOWQ27MEZUC7YEEYPZNVVR7THRC5265RRJT5A1111208; pdd_user_id=5722344946962; pdd_user_uin=NCX3F2DDNZ2KHCEFQF7AGFWOTE_GEXDA; rec_list_orders=rec_list_orders_bIzOsY; rec_list_personal=rec_list_personal_l316cx; JSESSIONID=702FDDC9E5D6E5C1E6CD043395B7EA10"
    pdd = PinDuoDuo(cookie)
    pdd.start()