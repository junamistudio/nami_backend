# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging
import os
import signal
import sys
import re
import inspect
import collections
import json
import yaml
from concurrent.futures import ThreadPoolExecutor

import tornado.log
from tornado import ioloop
from tornado.options import options
from tornado_swagger.setup import setup_swagger

from config import setting
from task.events import Events
from task.worker import celery_app

logger = logging.getLogger(__name__)


class BaseApplication(tornado.web.Application):
    pool_executor_cls = ThreadPoolExecutor
    max_workers = 4
    routes = None

    def __init__(self):
        settings = dict()
        settings.update({
            'upload_path': os.path.join(os.path.dirname(__file__), 'upload'),
            'static_path': os.path.join(os.path.dirname(__file__), 'static'),
            'cookie_secret': setting.COOKIE_SECRET,
            'xsrf_cookie_kwargs': dict(httponly=True),
            # 'xsrf_cookie_kwargs':dict(httponly=True, secure=True)
            # "xsrf_cookies": True,
        })

        settings.update(setting.PUB_CONF)
        if options.mode == "dev":
            setup_swagger(
                self.routes,
                swagger_url="/doc",
                api_base_url="/",
                schemes=["http"],
                security_definitions={
                    "Token": {
                        "type": "apiKey",
                        "name": "Authorization",
                        "in": "header"
                    }
                }
            )

        super(BaseApplication, self).__init__(self.routes, **settings)
        self.options = options

        self.io_loop = ioloop.IOLoop.current()

        self.capp = celery_app
        self.enable_capp_event = options.enable_capp_event
        self.events = None
        if self.enable_capp_event:
            self.events = Events(
                self.capp, db=10,
                key_prefix=options.service,
                persistent=True,
                enable_events=True,
                io_loop=self.io_loop,
                max_workers_in_memory=5000,
                max_tasks_in_memory=10000
            )
        self.started = False

    @classmethod
    def init_routes(cls, routes):
        cls.routes = routes

    def start(self):
        self.update_route()
        if self.options.init_data:
            logger.info("init_data ...")
            self.init_data()

        self.pool = self.pool_executor_cls(max_workers=self.max_workers)
        if self.enable_capp_event:
            logger.info("enable celery event ...")
            self.events.start()

        # self.listen(self.options.port, xheaders=True)
        self.started = True

        def signal_handler(signal, frame):
            logger.info('SIGNAL {} detected, shutting down'.format(signal))
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        self.io_loop.start()

    def stop(self):
        if self.started:
            logger.info('Application Stopping')
            if self.enable_capp_event:
                self.events.stop()
            self.pool.shutdown(wait=False)
            self.started = False

    def update_route(self):
        pass