#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""le.py"""

import argparse
import hashlib
import logging
import json
import os
import time

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from jwcrypto.common import base64url_encode, json_decode, json_encode
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

logging.basicConfig(level=logging.INFO)

PRODUCTION_CA = 'https://acme-v01.api.letsencrypt.org/directory'
TERM_OF_SERVICE = 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf'

get_nonce = lambda server: requests.get(server).headers.get('Replay-Nonce')
lookup = lambda server, k: requests.get(server).json().get(k)
get_challenge = lambda chs, k: [ch for ch in chs if ch['type'] == k][0]


def get_key(path):
    # type: (str) -> JWK
    with open(path, 'rb') as key_file:
        return JWK.from_pem(key_file.read())


def generate_header(jwk):
    # type: (JWK) -> dict
    header = dict(jwk=json_decode(jwk.export_public()))
    if 'kid' in header['jwk']:
        del header['jwk']['kid']
    if jwk.key_type == 'RSA':
        header['alg'] = 'RS256'
    elif jwk.key_type == 'EC':
        header['alg'] = {'P-256': 'ES256', 'P-384': 'ES384'}[jwk.key_curve]
    else:
        raise NotImplementedError('The key type is not supported')
    return header


def sign_request(payload, nonce, jwk):
    # type: (dict, str, JWK) -> None
    header = generate_header(jwk)
    protected = dict(nonce=nonce)
    jws = JWS(json_encode(payload).encode())
    jws.add_signature(jwk, header['alg'], protected, header)
    return json_decode(jws.serialize())


def new_registration(server, key, email):
    nonce = get_nonce(server)
    payload = {
        'resource': 'new-reg',
        'contact': ['mailto:%s' % email],
        'agreement': TERM_OF_SERVICE,
    }
    r = requests.post(
        lookup(server, 'new-reg'), json=sign_request(payload, nonce, key))
    if r.status_code != 201:  # Created
        raise IOError('ACME Request Failed: HTTP {} {}, {}'.format(
            r.status_code, r.reason, r.text))
    return r.json(), r.headers.get('Location')


def generate_key_authorization(key, token):
    # generate key authorization
    return '{}.{}'.format(token, key.thumbprint())
    # generate txt record (for dns-01)
    # txt_record = base64url_encode(hashlib.sha256(key_auth.encode('ascii')).digest())
    # return key_auth, txt_record.decode('ascii')


def new_authorization(server, key, domain):
    nonce = get_nonce(server)
    payload = {
        'resource': 'new-authz', \
        'identifier': {'type': 'dns', 'value': domain},
    }
    r = requests.post(
        lookup(server, 'new-authz'), json=sign_request(payload, nonce, key))
    if r.status_code == 201:  # Created
        return r.json()
    else:
        raise IOError('ACME Request Failed: HTTP {} {}, {}'.format(
            r.status_code, r.reason, r.text))


def get_authorization(uri):
    return requests.get(uri).json()


def validate_authorization(challenge, key_auth, key):
    nonce = get_nonce(challenge['uri'])
    payload = {
        'resource': 'challenge',
        'type': challenge['type'],
        'keyAuthorization': key_auth
    }
    r = requests.post(challenge['uri'], json=sign_request(payload, nonce, key))
    if r.status_code == 202:  # Accept
        return r.json()
    else:
        raise IOError('ACME Request Failed: HTTP {} {}, {}'.format(
            r.status_code, r.reason, r.text))


def issue_certificate(server, domains, cert_key, key):
    # generate csr
    from cryptography import x509
    from cryptography.x509 import NameOID
    assert domains
    try:
        domains = [unicode(domain) for domain in domains]
    except NameError:
        pass
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    san = x509.SubjectAlternativeName(
        [x509.DNSName(domain) for domain in domains])
    csr = x509.CertificateSigningRequestBuilder().subject_name(name) \
        .add_extension(san, critical=False).sign(cert_key, hashes.SHA256(), default_backend())
    csr = csr.public_bytes(serialization.Encoding.DER)
    # requests
    header = generate_header(key)
    nonce = get_nonce(server)
    payload = {
        'resource': 'new-cert',
        'csr': base64url_encode(csr),
    }
    r = requests.post(
        lookup(server, 'new-cert'), json=sign_request(payload, nonce, key))
    if r.status_code == 201:  # Created
        cert = x509.load_der_x509_certificate(
            r.content,
            default_backend()).public_bytes(serialization.Encoding.PEM)
        chain = r.links.get('up')
        if chain:
            inter_cert = requests.get(chain['url']).content
            inter_cert = x509.load_der_x509_certificate(
                inter_cert,
                default_backend()).public_bytes(serialization.Encoding.PEM)
        return cert + (inter_cert or b'')
    else:
        raise IOError('Issue Certificate Failed: {} {}: {}'.format(
            r.status_code, r.reason, r.text))


def authorize(server, key, method, domains, challenge_dir=None):
    for domain in domains:
        # 获取 challenge
        auth = new_authorization(server, key, domain)
        challenge = get_challenge(auth['challenges'], method)
        logging.debug('{}: challenge uri: {}'.format(domain, challenge['uri']))
        # 写入 challenge 文件
        token = challenge['token']
        key_auth = generate_key_authorization(key, token)
        if method.startswith('dns'):
            txt_record = base64url_encode(
                hashlib.sha256(key_auth.encode()).digest())
            logging.info('  "_acme-challenge.{}." IN TXT  "{}"'.format(
                domain, txt_record))
            try:
                input("Press enter to continue: ")
            except:  # for python2
                pass
        else:  # 非 dns 验证
            with open(os.path.join(challenge_dir, token), 'w') as token_file:
                token_file.write(key_auth)
        # 验证
        validate_authorization(challenge, key_auth, key)
        for _ in range(4):  # 尝试四次判断验证状态
            status = get_authorization(challenge['uri']).get('status')
            if status == 'valid':
                logging.info('Domain validate success: {}'.format(domain))
                break  # validate success
            elif status == 'pending':
                logging.info('Retry to get validate status')
                time.sleep(5)  # 5秒后再判断
            else:
                raise IOError('Validate Failed: Status: {}, {}'.format(status, challenge['uri']))
        else:
            raise IOError('Validate Failed.')


def load_account(path):
    if not os.path.isfile(path):  # 文件不存在
        jwk = JWK.generate(kty='EC', crv='P-384')
        return {'jwk': jwk, 'uri': None}
    else:
        with open(path) as account_file:
            account = json_decode(account_file.read())
        return {'jwk': JWK(**account['jwk']), 'uri': account['uri']}


def _reg(args):
    account = load_account(args.account)
    r, uri = new_registration(args.server, account['jwk'], args.email)
    data = json.dumps(
        dict(
            email=args.email,
            jwk=json_decode(account['jwk'].export_private()),
            uri=uri,
            registration=r),
        indent=4)
    with open(args.account, 'w') as account_file:
        account_file.write(data)
    logging.info('Registration finished.')


def _new(args):
    account = load_account(args.account)
    with open(args.key_file, 'rb') as key_file:
        cert_key = serialization.load_pem_private_key( \
            key_file.read(), None, default_backend())
    # authorize
    if args.type.startswith('dns'):
        authorize(args.server, account['jwk'], args.type, args.domain)
    elif args.challenge_dir is not None:
        authorize(args.server, account['jwk'], args.type, args.domain,
                  args.challenge_dir)
    else:
        raise IOError('challenge directory unknown')
    crt = issue_certificate(args.server, args.domain, cert_key, account['jwk'])
    with open(args.output, 'wb') as crt_file:
        crt_file.write(crt)
    logging.info('Certificate Issue finished')


def main():
    parser = argparse.ArgumentParser(prog='le.py')
    subparsers = parser.add_subparsers()

    # Server & Account
    parser.add_argument(
        '-s', '--server', help='The ACME server to use', default=PRODUCTION_CA)
    parser.add_argument(
        '-a', '--account', help='The account file', default='account.json')

    # account creation
    reg = subparsers.add_parser(
        'reg', help='Create a new account and register')
    reg.add_argument('email', type=str, help='Account email address')
    reg.set_defaults(func=_reg)

    # New certificate or renew certificate
    new = subparsers.add_parser(
        'new', help='New certificate or renew certificate')
    new.add_argument('domain', help='domains', nargs='+')
    new.add_argument(
        '-t',
        '--type',
        help='Authorize types ["dns-01", "tls-sni-01", "http-01"]')
    new.add_argument('-k', '--key-file', help='Certificate key file')
    new.add_argument(
        '--challenge-dir', help='ACME Challenge dir', default=None)
    new.add_argument('-o', '--output', help='Certificate file to output')
    new.set_defaults(func=_new)

    # args parse
    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        exit(0)

    args.func(args)


if __name__ == '__main__':
    main()
