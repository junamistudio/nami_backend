# -*- coding: utf-8 -*-
# Author: junami@126.com

import setting
from playhouse.pool import PooledMySQLDatabase
from playhouse.shortcuts import ReconnectMixin


class ReconnectPooledMySQLDatabase(ReconnectMixin, PooledMySQLDatabase):
    pass


database = ReconnectPooledMySQLDatabase(None, max_connections=20, stale_timeout=300, timeout=None)
database.init(
    database=setting.DB_BASE,
    host=setting.DB_HOST,
    port=int(setting.DB_PORT),
    user=setting.DB_USER,
    passwd=setting.DB_PASSWD,
    charset='utf8mb4',
)
