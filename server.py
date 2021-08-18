# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging
import atexit
import tornado

from tornado.options import define, parse_command_line, options
from tornado.log import LogFormatter
from app.nami_app import Application as NamiApp
from logging import NullHandler

define("service", default='app', help="start service flag", metavar='app|xxx', type=str)
define('port', default=8081, type=int)
define('mode', default='dev', metavar='dev|prd')
define('debug', default=False)
define('enable_capp_event', default=False)
define('init_data', default=False)
define('access_role', multiple=True)
parse_command_line()

logger = logging.getLogger(__name__)


def setup_logging():
    root_logger = logging.getLogger()
    fmt = '%(color)s[%(levelname)1.1s %(process)-5d %(asctime)s %(name)-15s:%(lineno)-4d]%(end_color)s %(message)s'
    formatter = LogFormatter(color=True, fmt=fmt)
    [log_handler.setFormatter(formatter) for log_handler in root_logger.handlers]

    for pkg_name in ["amqp", "peewee"]:
        logging.getLogger(pkg_name).addHandler(NullHandler())
        logging.getLogger(pkg_name).propagate = False

    if options.mode == 'dev':
        options.logging = 'debug'
    elif options.mode == 'prd':
        options.logging = 'info'
        logging.getLogger("tornado.access").addHandler(NullHandler())
        logging.getLogger("tornado.access").propagate = False


def runserver():
    app = NamiApp()

    setup_logging()

    atexit.register(app.stop)
    logger.info("Starting {}".format(options.service))

    server = tornado.httpserver.HTTPServer(app, xheaders=True)
    server.listen(options.port)
    server.start(num_processes=1)
    app.start()


if __name__ == '__main__':
    runserver()
