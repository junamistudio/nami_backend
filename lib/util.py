#!usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import random
import re
import time
import string
import urllib
import copy
import decimal
from cgi import FieldStorage
import datetime

import jwt
import paramiko
import simplejson
import unicodedata
from PIL import Image, ImageFont, ImageFilter, ImageDraw

from model import database
from pytz import timezone


def dump_json(data, pretty=False):
    def converter(o):
        if isinstance(o, datetime.date):
            return str(o)
        if isinstance(o, decimal.Decimal):
            return float(o)

    indent = None
    if pretty:
        indent = 2
    ret = json.dumps(data, default=converter, indent=indent, ensure_ascii=False)
    return ret


def setting_from_object(obj, mode='dev'):
    setting = {}
    if obj:
        tmp_dict = obj.get(mode, {}) if obj else {}
        setting.update(tmp_dict)
        setting.update(obj)

    configs = dict()
    for key in setting:
        if key.isupper():
            configs[key.lower()] = setting[key]

    return configs


def escape_shell_string(val):
    escaped = val.translate(
        str.maketrans(
            {"$": r"\$", "!": r"\!"}
        )
    )
    return escaped


def vmobile(mobile):
    return re.match(r"((13|14|15|18)\d{9}$)|(\w+[@]\w+[.]\w+)", mobile)


def generate_token(uid, uname, latest=None, secret=''):
    """
    生成用户json web token
    :return: jwt值
    """
    payload = {
        'uid': uid,
        'uname': uname,
        'lastLogin': latest if latest else datetime.datetime.now().strftime('%Y%m%d%H%M%S'),
    }
    return jwt.encode(payload, secret, algorithm='HS256')


def generate_md5(str_data):
    return hashlib.md5(str_data.encode(encoding='UTF-8')).hexdigest()


def generate_random_str(length=6, category="verify_code"):
    """
    生成随机字符串
    :param length: 
    :param category:
    :return: 
    """
    category_dict = {
        "verify_code": string.digits,
        "username": string.digits + string.ascii_letters
    }
    return ''.join([random.choice(category_dict.get(category)) for _ in range(length)])


def generate_salt(length=32):
    """
    生成随机盐
    :param length: 
    :return: 
    """
    chars = string.ascii_letters + string.digits
    return ''.join([random.choice(chars) for _ in range(length)])


def _hashed_with_salt(info, salt):
    """
    md5 + salt加密
    :param info: 待加密信息
    :param salt: 盐值
    :return: 加密后信息
    """
    m = hashlib.md5()
    info = info.encode('utf-8') if isinstance(info, str) else info
    salt = salt.encode('utf-8') if isinstance(salt, str) else salt
    m.update(info)
    m.update(salt)
    return m.hexdigest()


def hashed_login_pwd(pwd, salt):
    """
    加密登录密码
    :param pwd: 登录密码
    :return: 加密后的密码
    """
    return _hashed_with_salt(pwd, salt)


def valid_phone_number(phone_number):
    """
    手机号码合法性校验
    :param phone_number: 手机号
    :return: bool值
    """
    pattern = re.compile(r'^(13[0-9]|15[012356789]|17[0-9]|18[0-9]|14[57]|19[0-9]|16[0-9])[0-9]{8}$')
    return pattern.match(str(phone_number))


def valid_password(password):
    """
    密码合法性校验
    :param password: 密码
    :return: bool值
    """
    pattern = re.compile(r'^[\S]{10, }$')
    return pattern.match(str(password))


def mask_phone(phone):
    """
    加密手机号
    :param phone: 
    :return: 
    """
    if not valid_phone_number(phone):
        return ''
    return phone[0:3] + '****' + phone[7:]


def concat_params(params):
    pairs = []
    for key in sorted(params):
        if key == 'sig':
            continue
        val = params[key]
        if isinstance(val, str):
            val = urllib.quote_plus(val.encode('utf-8'))
        elif isinstance(val, dict):
            val = json.dumps(val).replace(' ', '')
        if not isinstance(val, FieldStorage):
            pairs.append("{}={}".format(key, val))
    return '&'.join(pairs)


def is_valid_idcard(idcard):
    """Validate id card is valid."""

    IDCARD_REGEX = '[1-9][0-9]{14}([0-9]{2}[0-9X])?'
    if not idcard:
        return False

    if isinstance(idcard, int):
        idcard = str(idcard)

    if not re.match(IDCARD_REGEX, idcard):
        return False

    if not (14 < len(idcard) < 19):
        return False

    # 地域判断
    # if idcard[:6] not in AREA_CODES:
    #     return False

    return True

    # factors = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    # items = [int(item) for item in idcard[:-1]]
    #
    # copulas = sum([a * b for a, b in zip(factors, items)])
    #
    # ckcodes = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    #
    # print idcard[-1], ckcodes[copulas % 11]
    # return ckcodes[copulas % 11].upper() == idcard[-1].upper()


def gen_sig(path_url, params, consumer_secret):
    params = concat_params(params)

    to_hash = u'{}?{}{}'.format(
        path_url, params, consumer_secret
    ).encode('utf-8').encode('hex')

    sig = hashlib.new('sha1', to_hash).hexdigest()
    return sig


class Row(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return None

    def __deepcopy__(self, memo=None):
        return Row(copy.deepcopy(dict(self)))


class UtilMixin(object):
    def find_subclasses(self, klass, include_self=False):
        accum = []
        for child in klass.__subclasses__():
            accum.extend(self.find_subclasses(child, True))
        if include_self:
            accum.append(klass)
        return accum

    @staticmethod
    def sendmsg(settings, mobile, content):
        url = "%s?accesskey=%s&secretkey=%s&mobile=%s&content=%s" % (
            settings['sms_gateway'], settings['sms_key'], settings['sms_secret'], mobile, urllib.quote_plus(content))
        result = simplejson.loads(urllib.urlopen(url).read())

        if int(result['result']) > 1:
            raise Exception('无法发送')

    @staticmethod
    def get_pages(total, per_page_num):
        pages = total / per_page_num
        if total % per_page_num != 0:
            pages += 1
        return pages


from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


class Crypt(object):
    def __init__(self):
        self.key = 'eCcGFZQj6PNoSSma31LR39rTzTbLkU8E'.encode('utf-8')
        self.mode = AES.MODE_CBC

    def encrypt(self, text):  # 加密
        count = len(text)
        if count % 16 != 0:
            add = 16 - (count % 16)
            text = text + ('\0' * add)

        cryptor = AES.new(self.key, self.mode, b'&y3dmpx-8sgnu%y+')
        self.ciphertext = cryptor.encrypt(text.encode('utf-8'))
        return b2a_hex(self.ciphertext).decode(encoding='utf-8')

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'&y3dmpx-8sgnu%y+')
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.decode().rstrip('\0')


import itsdangerous


class ExpCrypt(object):
    def __init__(self):
        self.key = '^&y3dmpx-8sgnu%y+8tr#%tce3xnxwb*@^2549n5g6%ur^fuyt'.encode('utf-8')
        self.expires = 60 * 30

    def encrypt(self, text):  # 加密
        cryptor = itsdangerous.TimedJSONWebSignatureSerializer(self.key, expires_in=self.expires)
        token = cryptor.dumps(text)
        return token.decode()

    def decrypt(self, text):
        decrypt = itsdangerous.TimedJSONWebSignatureSerializer(self.key, expires_in=self.expires)
        token = decrypt.loads(text)
        return token


def date() -> str:
    '''datetime'''
    now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    return now


def generate_tree(ls):
    target_result = []
    count = len(ls)
    for i in range(0, count):
        if "children" not in ls[i].keys():
            ls[i]["children"] = []
        for j in range(i + 1, count):
            if ls[i].get("id") == ls[j].get("parent_id"):
                ls[i]["children"].append(ls[j])
        if not ls[i].get("parent_id"):
            target_result.append(ls[i])
    return target_result


def upload_file(ip, port, user, local_file, remote_file, pkey=None):
    try:
        key = paramiko.RSAKey.from_private_key_file(pkey)
        t = paramiko.Transport((ip, port))
        t.connect(username=user, pkey=key)
        sftp = paramiko.SFTPClient.from_transport(t)

        sftp.put(local_file, remote_file)
        t.close()
        sftp.close()
    except Exception as e:
        t.close()
        sftp.close()
        print(e)


def upload_files(ip, port, user, local_path, remote_path, pkey=None):
    try:
        key = paramiko.RSAKey.from_private_key_file(pkey)
        t = paramiko.Transport((ip, port))
        t.connect(username=user, pkey=key)
    except Exception as e:
        raise e
    else:
        sftp = paramiko.SFTPClient.from_transport(t)

        files = os.listdir(local_path)
        for f in files:
            sftp.put(os.path.join(local_path, f), os.path.join(remote_path, f))
        t.close()
        sftp.close()


def format_time(time_stamp, tz=timezone('Asia/Shanghai'), fmt="%Y-%m-%d %H:%M:%S.%f"):
    dt = datetime.datetime.fromtimestamp(time_stamp, tz=tz)
    return dt.strftime(fmt)


def str_normalize(val):
    return unicodedata.normalize('NFKD', val)
