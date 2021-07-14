# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging

from tornado.web import url

from app.base import BaseApplication
from handler import (
    i_am_ok,
    table1,
    table2
)

logger = logging.getLogger(__name__)


def policy(auth=False):
    return {"auth": auth}


app_routes = [
    url(r"/are_you_ok", i_am_ok.IamOK, name='', kwargs=policy(auth=False)),
]

app_routes.extend(table1.urls)
app_routes.extend(table2.urls)


class Application(BaseApplication):
    SERVICE_NAME = 'APP1'


Application.init_routes(app_routes)
