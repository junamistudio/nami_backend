# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging
import random
import time
from datetime import datetime

from jsonschema import validate
from tornado.web import url

from config import status
from handler import UserBaseHandler
from model import database
from model.models import Table1

logger = logging.getLogger()


class TableOneHandler(UserBaseHandler):

    def get(self):
        """
        ---
        tags:
        - Table1
        summary: Table1 List
        parameters:
        -   in: query
            name: page
            required: false
        produces:
        - "application/json"
        responses:
            200:
                example: {
                }
        security:
        -   Token: []
        """
        param_schema = {
            "type": "object",
            "properties": {
                "page": {"type": "string", "pattern": r"^([0-9]+)$"},
                "show_num": {"type": "string", "pattern": r"^([0-9]+)$"}
            }
        }
        req_param = self.req.query
        validate(req_param, param_schema)
        page = req_param.get("page", 1)
        show_num = req_param.get("show_num", 20)

        res = Table1.select().paginate(int(page), int(show_num)).dicts()

        return self.out(status.success.code, data=list(res), msg=status.success.msg)

    def put(self):
        """
        ---
        tags:
        - Table1
        summary: generate random data array
        produces:
        - "application/json"
        responses:
            200:
                example: {
                }
        security:
        -   Token: []
        """
        random_row = [
            {
                "gmt_created": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "value": random.randint(0, 100)
            } for _ in range(10)
        ]
        with database.atomic():
            Table1.insert_many(random_row).execute()

        return self.out(status.success.code, data=random_row, msg=status.success.msg)


def policy(auth=False):
    return {"auth": auth}


urls = [
    url(r"/table1", TableOneHandler, kwargs=policy(auth=True))
]
