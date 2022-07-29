# WeChatPayV3

Python微信支付V3

- 目前只实现了H5支付，后续补充其他。如有问题联系，谢谢！

```python

from main import WeChatPayV3
from utils import gen_order_number

mchid = 1234567890  # 商户号
appid = "wx1234567890123456"  # appid
v3key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"  # API V3 密钥
apiclient_key = "/Users/yangyuexiong/Desktop/apiclient_key.pem"  # 私钥证书路径
serial_no = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234"  # 商户号证书序列号
notify_url = "https://www.xxx.com/api/wxpay/notifyUrl"  # 回调地址

wx_pay = WeChatPayV3(
    mchid=mchid,
    appid=appid,
    v3key=v3key,
    apiclient_key=apiclient_key,
    serial_no=serial_no,
    notify_url=notify_url
)

order_number = gen_order_number()
resp = wx_pay.pay(
    out_trade_no="202206301330151656567015",
    total=1,
    description="测试",
    ip="127.0.0.1"
)
print(resp)
```

- 下单 [test_pay.py](./test/test_pay.py)
- 回调 [test_notify.py](./test/test_notify.py)
- 主动查询、关闭 [test_pay_query.py](./test/test_pay_query.py)
