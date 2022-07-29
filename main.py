# -*- coding: utf-8 -*-
# @Time    : 2022/7/1 17:44
# @Author  : yangyuexiong
# @Email   : yang6333yyx@126.com
# @File    : main.py
# @Software: PyCharm


import json

from base64 import b64encode, b64decode

import requests
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils import *


class WeChatPayV3:
    """微信支付API V3"""

    def __init__(self, mchid, appid, v3key, apiclient_key, notify_url, serial_no):
        """

        :param mchid: 商户号
        :param appid: appid
        :param v3key: API V3 密钥
        :param apiclient_key: 私钥证书路径
        :param notify_url: 回调地址
        :param serial_no: 商户号证书序列号
        """
        self.mchid = mchid
        self.appid = appid
        self.v3key = v3key
        self.apiclient_key = apiclient_key
        self.notify_url = notify_url
        self.serial_no = serial_no

        self.base_pay_url = "https://api.mch.weixin.qq.com"
        self.h5_pay_url = "/v3/pay/transactions/h5"
        self.certificates_url = "/v3/certificates"

    @staticmethod
    def gen_pay_sign(method, url, timestamp, random_str, req_json):
        """
        构造支付相关验签名串
        :param method: HTTP请求方法\n
        :param url: URL\n
        :param timestamp: 请求时间戳\n
        :param random_str: 请求随机串\n
        :param req_json: 请求报文主体\n
        :return:
        """
        """
        HTTP请求方法\n
        URL\n
        请求时间戳\n
        请求随机串\n
        请求报文主体\n
        """
        sign_list = [
            method,
            url,
            timestamp,
            random_str,
            req_json
        ]
        sign_str = '\n'.join(sign_list) + '\n'
        return sign_str

    @staticmethod
    def gen_notify_sign(timestamp, nonce, body):
        """
        构造回调相关验签名串
        :param timestamp:
        :param nonce:
        :param body:
        :return:
        """
        """
        应答时间戳\n
        应答随机串\n
        应答报文主体\n
        """

        sign_list = [
            timestamp,
            nonce,
            body
        ]
        sign_str = '\n'.join(sign_list) + '\n'
        return sign_str

    @staticmethod
    def gen_sign_str(method, url, timestamp, random_str, data):
        """
        生成请求证书的签名串
        :param method: HTTP请求方法\n
        :param url: URL\n
        :param timestamp: 请求时间戳\n
        :param random_str: 请求随机串\n
        :param data: 请求报文主体\n
        :return:
        :return:
        """

        """
        HTTP请求方法\n
        URL\n
        请求时间戳\n
        请求随机串\n
        请求报文主体\n
        """
        sign_list = [
            method,
            url,
            timestamp,
            random_str,
            data
        ]
        sign_str = '\n'.join(sign_list) + '\n'
        return sign_str

    def gen_cert(self):
        """应答签名验证(微信平台证书)"""

        url = f"{self.base_pay_url}{self.certificates_url}"
        random_str = gen_random_str()
        timestamp = gen_timestamp()

        # 生成请求证书的签名串
        sign_str = self.gen_sign_str(
            method='GET',
            url=self.certificates_url,
            timestamp=timestamp,
            random_str=random_str,
            data=""
        )

        # 生成签名
        sign = self.sign(sign_str)

        # 生成 Authorization
        authorization = self.gen_authorization(
            random_str=random_str,
            sign=sign,
            timestamp=timestamp,
        )

        print(authorization)

        # 生成HTTP请求头
        headers = {
            'Content-Type': 'application/json; charset=UTF-8',
            'Accept': 'application/json',
            'Authorization': authorization
        }

        # 微信平台证书
        response = requests.get(url, headers=headers, verify=False)
        cert = response.json()
        return cert

    def sign(self, sign_str):
        """
        签名加密
        :param sign_str: 验签名串
        :return:
        """

        rsa_key = RSA.importKey(open(self.apiclient_key).read())
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(sign_str.encode('utf8'))
        sign = b64encode(signer.sign(digest)).decode('utf-8')
        return sign

    def gen_authorization(self, random_str, sign, timestamp):
        """
        生成:Authorization
        :param random_str: 32位随机字符串
        :param sign: 签名
        :param timestamp: 时间戳
        :return:
        """

        authorization = 'WECHATPAY2-SHA256-RSA2048  ' \
                        'mchid="{mchid}",' \
                        'nonce_str="{random_str}",' \
                        'signature="{sign}",' \
                        'timestamp="{timestamp}",' \
                        'serial_no="{serial_no}"'. \
            format(mchid=self.mchid,
                   random_str=random_str,
                   sign=sign,
                   timestamp=timestamp,
                   serial_no=self.serial_no)

        return authorization

    def pay(self, out_trade_no, total, description, ip):
        """
        获取h5支付的url
        :param out_trade_no: 订单号
        :param total: 总金额
        :param description: 描述
        :param ip: 客户端ip地址
        :return:
        """
        try:
            pay_url = f"{self.base_pay_url}{self.h5_pay_url}"
            random_str = gen_random_str()
            timestamp = gen_timestamp()

            data = {
                "mchid": self.mchid,
                "out_trade_no": out_trade_no,
                "appid": self.appid,
                "description": description,
                "notify_url": self.notify_url,
                "amount": {
                    "total": total,
                    "currency": "CNY"
                },
                "scene_info": {
                    "payer_client_ip": ip,
                    "h5_info": {
                        "type": "Wap"
                    }
                }
            }
            data = json.dumps(data)  # 序列化成JSON字符串

            sign_str = self.gen_pay_sign(
                method="POST",
                url=self.h5_pay_url,
                timestamp=timestamp,
                random_str=random_str,
                req_json=data
            )
            sign = self.sign(sign_str=sign_str)
            print(sign)

            authorization = self.gen_authorization(
                random_str=random_str,
                sign=sign,
                timestamp=timestamp,
            )
            print(authorization)

            headers = {
                'Content-Type': 'application/json; charset=UTF-8',
                'Authorization': authorization
            }
            response = requests.post(pay_url, data=data, headers=headers, verify=False)
            print(response)
            return response.json()
        except BaseException as e:
            print(f"支付失败:{str(e)}")
            return {"error": f"支付失败:{str(e)}"}

    def decrypt(self, nonce, ciphertext, associated_data):
        """
        证书和回调报文解密
        :param nonce: 加密使用的随机串初始化向量
        :param ciphertext: Base64编码后的密文
        :param associated_data: 附加数据包（可能为空）
        :return :解密后的数据
        """

        key_bytes = str.encode(self.v3key)  # API V3秘钥
        nonce_bytes = str.encode(nonce)
        ad_bytes = str.encode(associated_data)
        data = b64decode(ciphertext)
        aesgcm = AESGCM(key_bytes)
        certificate = aesgcm.decrypt(nonce_bytes, data, ad_bytes).decode('utf-8')
        return certificate

    def decrypt_notify_cert(self):
        """获取微信平台证书并解密"""

        cert = self.gen_cert()
        nonce = cert["data"][0]['encrypt_certificate']['nonce']
        ciphertext = cert["data"][0]['encrypt_certificate']['ciphertext']
        associated_data = cert["data"][0]['encrypt_certificate']['associated_data']

        # print('=== cert ===')
        # print(cert)

        certificate = self.decrypt(
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data=associated_data
        )
        # print('=== certificate ===')
        # print(certificate)
        return certificate

    def check_notify_sign(self, timestamp, nonce, body, certificate, signature):
        """
        验签
        :param timestamp:
        :param nonce:
        :param body:
        :param certificate: 微信平台证书
        :param signature:
        :return:
        """

        body = body.decode("utf-8")
        sign_str = self.gen_notify_sign(timestamp, nonce, body)
        publicKey = RSA.importKey(certificate)
        h = SHA256.new(sign_str.encode('UTF-8'))  # 对响应体进行RSA加密
        verifier = pkcs1_15.new(publicKey)  # 创建验证对象
        return verifier.verify(h, b64decode(signature))  # 验签

    def decode_notify_data(self, req_json):
        """
        回调的请求参数
        :param req_json:
        :return:
        """
        try:
            ciphertext = req_json['resource']['ciphertext']
            nonce = req_json['resource']['nonce']
            associated_data = req_json['resource']['associated_data']
            cipher = AES.new(self.v3key.encode(), AES.MODE_GCM, nonce=nonce.encode())
            cipher.update(associated_data.encode())
            en_data = b64decode(ciphertext.encode('utf-8'))
            auth_tag = en_data[-16:]
            _en_data = en_data[:-16]
            plaintext = cipher.decrypt_and_verify(_en_data, auth_tag)
            decode_json = json.loads(plaintext.decode())
            return decode_json
        except Exception as e:
            print(f"解密回调失败:{str(e)}")
            return None

    def query_wx_pay_order(self, transaction_id):
        """
        微信支付订单号查询
        :param transaction_id: 订单号
        :return:
        """

        try:
            url = f"{self.base_pay_url}/v3/pay/transactions/out-trade-no/{transaction_id}?mchid={self.mchid}"
            random_str = gen_random_str()
            timestamp = gen_timestamp()

            sign_str = self.gen_pay_sign(
                method="GET",
                url=f"/v3/pay/transactions/out-trade-no/{transaction_id}?mchid={self.mchid}",
                timestamp=timestamp,
                random_str=random_str,
                req_json=""
            )
            sign = self.sign(sign_str=sign_str)
            print(sign)

            authorization = self.gen_authorization(
                random_str=random_str,
                sign=sign,
                timestamp=timestamp,
            )
            print(authorization)

            headers = {
                'Content-Type': 'application/json; charset=UTF-8',
                'Authorization': authorization
            }
            response = requests.get(url, headers=headers, verify=False)
            print(response)
            return response.json()
        except BaseException as e:
            print(f"商户订单号查询失败:{str(e)}")
            return {"error": f"商户订单号查询失败:{str(e)}"}

    def query_mch_order(self, out_trade_no):
        """
        商户订单号查询
        :param out_trade_no: 订单号
        :return:
        """

        try:
            url = f"{self.base_pay_url}/v3/pay/transactions/out-trade-no/{out_trade_no}?mchid={self.mchid}"
            random_str = gen_random_str()
            timestamp = gen_timestamp()

            sign_str = self.gen_pay_sign(
                method="GET",
                url=f"/v3/pay/transactions/out-trade-no/{out_trade_no}?mchid={self.mchid}",
                timestamp=timestamp,
                random_str=random_str,
                req_json=""
            )
            sign = self.sign(sign_str=sign_str)
            print(sign)

            authorization = self.gen_authorization(
                random_str=random_str,
                sign=sign,
                timestamp=timestamp,
            )
            print(authorization)

            headers = {
                'Content-Type': 'application/json; charset=UTF-8',
                'Authorization': authorization
            }
            response = requests.get(url, headers=headers, verify=False)
            print(response)
            return response.json()
        except BaseException as e:
            print(f"商户订单号查询失败:{str(e)}")
            return {"error": f"商户订单号查询失败:{str(e)}"}

    def close(self, out_trade_no):
        """关闭订单"""

        try:
            url = f"{self.base_pay_url}/v3/pay/transactions/out-trade-no/{out_trade_no}/close"
            random_str = gen_random_str()
            timestamp = gen_timestamp()

            data = {
                "mchid": self.mchid
            }
            data = json.dumps(data)  # 序列化成JSON字符串

            sign_str = self.gen_pay_sign(
                method="POST",
                url=f"/v3/pay/transactions/out-trade-no/{out_trade_no}/close",
                timestamp=timestamp,
                random_str=random_str,
                req_json=data
            )
            sign = self.sign(sign_str=sign_str)
            print(sign)

            authorization = self.gen_authorization(
                random_str=random_str,
                sign=sign,
                timestamp=timestamp,
            )
            print(authorization)

            headers = {
                'Content-Type': 'application/json; charset=UTF-8',
                'Authorization': authorization
            }
            response = requests.post(url, data=data, headers=headers, verify=False)
            print(response)
            return True
        except BaseException as e:
            print(f"关闭订单失败:{str(e)}")
            return {"error": f"关闭订单失败:{str(e)}"}
