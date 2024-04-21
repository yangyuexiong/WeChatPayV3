# -*- coding: utf-8 -*-
# @Time    : 2022/6/12 13:38
# @Author  : yangyuexiong
# @Email   : yang6333yyx@126.com
# @File    : test_pay.py
# @Software: PyCharm

import json

from config import *
from main import WeChatPayV3
from utils import gen_order_number

wx_pay = WeChatPayV3(
    mchid=mchid,
    appid=appid,
    v3key=v3key,
    apiclient_key=apiclient_key,
    serial_no=serial_no,
    notify_url=notify_url,
    pay_type="mini"
)

if __name__ == '__main__':
    order_number = gen_order_number()
    resp = wx_pay.pay(
        out_trade_no=order_number,
        total=1,
        description="测试",
        ip="127.0.0.1",
        openid="omScQ7XY4LM-FyCiJmJH6H9r2Zxo"
    )
    print(resp)

    print(json.dumps(resp, ensure_ascii=False))
