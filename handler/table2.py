# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging
from datetime import datetime

from jsonschema import validate
from tornado.web import url

from config import status
from handler import UserBaseHandler
from model import database
from model.models import Table1, Table2, Value

logger = logging.getLogger()


class TableTwoHandler(UserBaseHandler):

    def get(self):
        """
        ---
        tags:
        - Table2
        summary: Table2 List
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
        show_num = req_param.get("show_num", 100)

        res = Table2.select().paginate(int(page), int(show_num)).dicts()

        return self.out(status.success.code, data=list(res), msg=status.success.msg)

    def post(self):
        """
        ---
        tags:
        - Table2
        summary: save the current chart data from front
        produces:
        - "application/json"
        parameters:
        -   in: body
            name: body
            required: true
            example: {
                "title": "",
                "rows": [
                    {
                        "id": 100,
                        "value": 66
                    }
                ]
            }
        responses:
            200:
                example: {
                }
        security:
        -   Token: []
        """
        json_schema = {
            "type": "object",
            "properties": {
                "snapshot": {"type": "string"},
                "rows": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["gmt_created", "value"],
                        "properties": {
                            "gmt_created": {"type": "string"},
                            "value": {"type": "number"},
                        }
                    }
                }
            }
        }
        json_data = self.req.json
        validate(json_data, json_schema)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snapshot = json_data.get('snapshot', now)
        columns = json_data.get('rows', [])
        columns = [{**row, 'snapshot': snapshot, 'table1_id': row.get('id'), 'id': None} for row in columns]
        with database.atomic():
            Table2.insert_many(columns).execute()

        return self.out(status.success.code, msg=status.success.msg)

    def patch(self):
        """
        ---
        tags:
        - Table2
        summary: save the current chart data from table1
        produces:
        - "application/json"
        parameters:
        -   in: body
            name: body
            required: true
            example: {
                "title": ""
            }
        responses:
            200:
                example: {
                }
        security:
        -   Token: []
        """
        json_schema = {
            "type": "object",
            "properties": {
                "snapshot": {"type": "string"}
            }
        }
        json_data = self.req.json
        validate(json_data, json_schema)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snapshot = json_data.get('snapshot', now)

        res = (
            Table2.insert_from(
                Table1.select(
                    Value(snapshot).alias('prd_db_id'), Table1.id, Table1.value
                ),
                fields=[Table2.snapshot, Table2.table1_id, Table2.value]
            ).execute()
        )

        return self.out(status.success.code, data=res, msg=status.success.msg)


def policy(auth=False):
    return {"auth": auth}


urls = [
    url(r"/table2", TableTwoHandler, kwargs=policy(auth=True))
]
