# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging

from tornado.web import url

from app.base import BaseApplication
from handler import (
    i_am_ok
)

logger = logging.getLogger(__name__)


def policy(auth=False):
    return {"auth": auth}


app_routes = [
    url(r"/are_you_ok", i_am_ok.IamOK, name='', kwargs=policy(auth=False)),
]


class Application(BaseApplication):
    SERVICE_NAME = 'APP2'


Application.init_routes(app_routes)
