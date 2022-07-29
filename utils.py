# -*- coding: utf-8 -*-
# @Time    : 2022/7/29 10:48
# @Author  : yangyuexiong
# @Email   : yang6333yyx@126.com
# @File    : utils.py
# @Software: PyCharm

import time
import random
import string

import uuid


def gen_api_v3_key():
    """生成API V3 密钥"""

    API_V3_KEY = "".join(str(uuid.uuid4()).split("-")).upper()
    return API_V3_KEY


def gen_random_str(length=32):
    """
    生成随机字符串
    :param length:
    :return: 32位随机字符串
    """

    random_str = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    return random_str


def gen_timestamp():
    """
    时间戳
    :return:
    """
    return str(int(time.time()))


def gen_order_number(prefix="", suffix=""):
    """
    生成订单号
    """
    order_no = f"{prefix}{time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))}{int(time.time())}{suffix}"
    return order_no


if __name__ == '__main__':
    v3_key = gen_api_v3_key()
    print(v3_key)

    random_str = gen_random_str()
    print(random_str)

    timestamp = gen_timestamp()
    print(timestamp)

    order_number = gen_order_number()
    print(order_number)
