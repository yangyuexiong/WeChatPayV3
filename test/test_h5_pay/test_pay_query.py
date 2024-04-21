# -*- coding: utf-8 -*-
# @Time    : 2022/7/18 12:38
# @Author  : yangyuexiong
# @Email   : yang6333yyx@126.com
# @File    : test_pay_query.py
# @Software: PyCharm

from config import *
from main import WeChatPayV3

wx_pay = WeChatPayV3(
    mchid=mchid,
    appid=appid,
    v3key=v3key,
    apiclient_key=apiclient_key,
    serial_no=serial_no,
    notify_url=notify_url
)

if __name__ == '__main__':
    resp1 = wx_pay.close(out_trade_no="202207041132481656905568")
    resp2 = wx_pay.query_mch_order(out_trade_no="202207041449361656917376")
    resp3 = wx_pay.query_wx_pay_order(transaction_id="202207041449361656917376")
    print(resp1)
    print(resp2)
    print(resp3)
