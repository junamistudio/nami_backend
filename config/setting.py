# -*- coding: utf-8 -*-
# Author: junami@126.com

import os
import logging

from base64 import b64encode
from uuid import uuid4

JWT_SECRET = os.getenv('JWT_SECRET', '99a6afea88fc0ee763ebe9574c1d1b98')

DB_HOST = os.getenv('DB_HOST', '10.168.1.171')
DB_USER = os.getenv('DB_USER', 'app')
DB_PASSWD = os.getenv('DB_PASSWD', '1234qwer')
DB_PORT = os.getenv('DB_PORT', 3306)
DB_BASE = os.getenv('DB_BASE', 'app')

REDIS_HOST = os.getenv('REDIS_HOST', '192.168.141.75')
REDIS_PORT = os.getenv('REDIS_PORT', 6379)
REDIS_PASSWD = os.getenv('REDIS_PASSWD', '123456')
REDIS_DB = os.getenv('REDIS_DB', 0)

DEFAULT_MQ_ADDR = os.getenv('DEFAULT_MQ_ADDR', '192.168.141.75')
DEFAULT_MQ_PORT = 5672
DEFAULT_MQ_VHOST = '/'
DEFAULT_MQ_USER = os.getenv('DEFAULT_MQ_USER', 'root')
DEFAULT_MQ_PWD = os.getenv('DEFAULT_MQ_PWD', '123456')

COOKIE_SECRET = b64encode(uuid4().bytes + uuid4().bytes)

TIME_ZONE = 'Asia/Shanghai'
USE_TZ = True
CELERY_BEAT_TZ_AWARE = True

PUB_CONF = {
    'TITLE': 'DMS',

    'LOG_LEVEL': logging.DEBUG,

    'DB_HOST': DB_HOST,
    'DB_PORT': int(DB_PORT),
    'DB_USER': DB_USER,
    'DB_PASSWD': DB_PASSWD,
    'DB_BASE': DB_BASE,

    # redis配置
    'REDIS_HOST': REDIS_HOST,
    'REDIS_PORT': int(REDIS_PORT),
    'REDIS_PASSWD': REDIS_PASSWD,
    'REDIS_DB': int(REDIS_DB),

    # jwt
    'JWT_SECRET': JWT_SECRET,

}
