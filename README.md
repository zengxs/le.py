# le.py

## 安装

```sh
pip install -r requirements.txt
curl -LO https://github.com/zengxs667/le.py/raw/master/le.py
chmod +x le.py
```

## Usage

~~~
usage: le.py [-h] [-s SERVER] [-a ACCOUNT] {reg,new} ...

positional arguments:
  {reg,new}
    reg                 Create a new account and register
    new                 New certificate or renew certificate

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        The ACME server to use
  -a ACCOUNT, --account ACCOUNT
                        The account file
~~~

## 创建账户

```sh
./le.py -a ~/account.json  reg yourmail@example.org
```

这将为你创建一个 Let's Encrypt 账户，所有的操作都必须有一个账户才能继续操作。
`-a` 参数指定了将账户保存在你的 HOME 目录下的 `account.json` 文件中。
如果没有 `-a` 参数，则默认使用当前目录中的 `account.json` 文件。

如果显示 `INFO:root:Registration finished.` 表示注册成功。

## 申请证书

Let's Encrypt 目前支持的证书密钥类型包括：
+ RSA
  - 2048
  - 4096
  - 8192
+ ECC
  - P-256 (prime256v1)
  - P-384 (secp384r1)

### DNS 验证

```sh
# 生成 RSA 密钥
# openssl genrsa 2048 > key.pem
# 生成 EC256 密钥
# openssl ecparam -genkey -name prime256v1 -noout -out key.pem
openssl genrsa 2048 > key.pem
./le.py -a ~/account.json  new -t dns-01 -k key.pem -o crt.pem domain1.example.org
```

### HTTP 验证

```sh
openssl genrsa 2048 > key.pem
./le.py -a ~/account.json new -t http-01 -k key.pem -o crt.pem --challenge-dir /usr/share/nginx/acme domain1.example.org
```

当然，执行这一步操作之前需要在 Web 服务器中将 `/.well-known/acme-challenge` 指向 `/usr/share/nginx/acme` 文件夹。在 Nginx 中将如下语句放入 Server 段即可：

```nginx
location ^~ /.well-known/acme-challenge {
    default_type "text/plain";
    alias /usr/share/nginx/acme;
}
```

执行完之后显示 `INFO:root:Certificate issue finished` 表示成功，此时 `crt.pem` 就是包含了证书链的证书。

## 自动 renew 证书

要自动 renew 证书只需要设置一下 crontab 即可：

~~~
* * * * */4 /root/le.py -a /root/account.json new -t http-01 -k /etc/nginx/ssl/private/key.pem -o /etc/nginx/ssl/crt.pem --challenge-dir /usr/share/nginx/acme domain1.example.org && nginx -s reload
~~~

上面的 crontab 任务每 6 周 renew 一次证书并自动重启 Nginx 加载新证书。
