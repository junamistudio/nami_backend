# -*- coding: utf-8 -*-
# Author: junami@126.com

import time
import random
import pandas
import datetime
import logging
from peewee import *

from model import BaseModel
from lib.permission import Permission, UserNeed, RoleNeed, ItemNeed, DeptNeed
from playhouse.shortcuts import model_to_dict
from tabulate import tabulate

logger = logging.getLogger()


class UnknownField(object):
    def __init__(self, *_, **__): pass


class Table1(BaseModel):
    id = BigAutoField()
    gmt_created = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")])
    gmt_modified = DateTimeField(constraints=[SQL("DEFAULT 0000-00-00 00:00:00")])
    create_user = CharField()
    modify_user = CharField(null=True)
    value = IntegerField(null=True)

    class Meta:
        table_name = 'table1'
        indexes = (
            (('gmt_created',), True),
        )


class Table2(BaseModel):
    id = BigAutoField()
    table1_id = BigIntegerField()
    gmt_created = DateTimeField(constraints=[SQL("DEFAULT CURRENT_TIMESTAMP")])
    gmt_modified = DateTimeField(constraints=[SQL("DEFAULT 0000-00-00 00:00:00")])
    snapshot = DateTimeField(constraints=[SQL("DEFAULT 0000-00-00 00:00:00")])
    value = IntegerField(null=True)

    class Meta:
        table_name = 'table2'
        indexes = (
            (('gmt_created',), True),
        )
