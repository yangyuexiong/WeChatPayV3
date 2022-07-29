# -*- coding: utf-8 -*-
# @Time    : 2022/7/18 11:05
# @Author  : yangyuexiong
# @Email   : yang6333yyx@126.com
# @File    : test_notify.py
# @Software: PyCharm

import json

from config import *
from main import WeChatPayV3

# 微信传过来的headers
notify_headers = {
    "Accept": "*/*",
    "Connection": "close",
    "Content-Length": "911",
    "Content-Type": "application/json",
    "Host": "120.24.214.173:6000",
    "Pragma": "no-cache",
    "User-Agent": "Mozilla/4.0",
    "Wechatpay-Nonce": "nbu7CThORr0vuGRQkS8Hb3oaYd3ZxT6C",
    "Wechatpay-Serial": "63145E52D4226CCFCD0716A11AB9BB09FA91D60E",
    "Wechatpay-Signature": "nsigluIVyQISZQSLl5sdbjSFX2U8gqSQS7sIDDHCiXSoO7Uc87b9ldLkJU5lWCc8eFlictCe+oylO/3M7UvO3gQJVOarGxV9d8h3EnfzQPg/6w/dqEBWhOoKikr9gxtry4Hc2Rcs1DG3PctLmNHQqwiKYgQTpKKv66MlEU/5BG2rbujdbM0DOB9b+oTIuk5l0i26RH95gRb5B2JGB65hWXN5tTZiw5uH3J4Nx57A7PYUQt3kGC3fOakNq4u2YbcH4fZlJIzVsDA/v/hin2nsbpktHoX/4m9yFCZ/si/clqTUGfIANHF6grG5ifnc+T5r8XJXWh/14Ao9sfbEKqbuNA==",
    "Wechatpay-Signature-Type": "WECHATPAY2-SHA256-RSA2048",
    "Wechatpay-Timestamp": "1658114334",
    "X-Forwarded-For": "101.226.103.24"
}

# 微信传过来的body
notify_body = b'{"id":"06c48925-ef9b-53d9-ab87-923927c035ce","create_time":"2022-07-18T11:18:54+08:00","resource_type":"encrypt-resource","event_type":"TRANSACTION.SUCCESS","summary":"\xe6\x94\xaf\xe4\xbb\x98\xe6\x88\x90\xe5\x8a\x9f","resource":{"original_type":"transaction","algorithm":"AEAD_AES_256_GCM","ciphertext":"25MwKvqsIRp1iIlSVl1RfoN6vbAVWlWBmpbbdB7sN80UndsH7lygdUEVzcA8tMGx/66wNbiyegau09tdcFMLLTL5/JKbAPvVqVCkvQnkbFh861MTxRMPktGH3xeVKDp0TjGexVpufuACvVGDLi9AJO4BwLDS7XFsGxpH9tNg1mFSUvOgAGBN4bdRHPYpZ3WwfuQKK5zVMmdgeIZ0AuOoRLLIMJAzLPyTgR4u/ZWkaXZrCTiEi+MqBay2yxFTgvyEE6gkcPfsFFGq5AfSBHB6Qzj3dHolYA5fZ1pQ7308Y7V5Zr05hohKByZLNJugcrxjeFY+JBmFUINbNonSL723+AgZrIlwG1zLGk+ZSJtrijRyFy+c8NoDigigFEd/hr5IfcKCpPQoMDZbSkoK9nsFON1To8/rhZT6AImQ1TicqAO2wAsVez/09U6Er4uz6+CvFSVQiOxPV5rc7RKirqru1/5aoprKePdJLRWIRJNL3EpQ9KNLL8kePhA9kFDU+6o3nciDrpxjA2y1OIEuQTD/gsJGP0GPug1lwfCBcQRLqWDRDI6Lr2kyKbwZQfQcn0R+SofkNMKD","associated_data":"transaction","nonce":"jA3xBh3ZFOHs"}}'

timestamp = notify_headers.get('Wechatpay-Timestamp')
nonce = notify_headers.get('Wechatpay-Nonce')
data = notify_body
signature = notify_headers.get('Wechatpay-Signature')

wx_pay = WeChatPayV3(
    mchid=mchid,
    appid=appid,
    v3key=v3key,
    apiclient_key=apiclient_key,
    serial_no=serial_no,
    notify_url=notify_url
)

if __name__ == '__main__':
    # 获取微信平台证书并解密
    certificate = wx_pay.decrypt_notify_cert()

    # 验签
    try:
        check = wx_pay.check_notify_sign(
            timestamp=timestamp,
            nonce=nonce,
            body=data,
            certificate=certificate,
            signature=signature
        )
        print(f"check:{check}")
    except BaseException as e:
        print(f"验签失败:{str(e)}")

    # 解密
    try:
        json_data = json.loads(data.decode("utf-8"))
        print('=== json_data ===')
        print(json_data)
    except Exception as e:
        print(f"回调参数转json失败！{e}")
        raise

    resp_json = wx_pay.decode_notify_data(json_data)
    print('=== resp_json ===')
    print(resp_json)
    if not resp_json:
        print('error')
