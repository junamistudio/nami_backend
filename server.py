# -*- coding: utf-8 -*-
# Author: junami@126.com

import logging
import atexit
import tornado

from tornado.options import define, parse_command_line, options
from tornado.log import LogFormatter, enable_pretty_logging
from app.app1 import Application as APP1
from app.app1 import Application as APP2
from logging import NullHandler
from config import setting

define("service", default='dms', help="start service flag", metavar='app1|app2', type=str)
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
    app = None
    if options.service == 'app1':
        app = APP1()
    elif options.service == 'app2':
        app = APP2()
    setup_logging()

    atexit.register(app.stop)
    logger.info("Starting {}".format(options.service))

    server = tornado.httpserver.HTTPServer(app, xheaders=True)
    server.listen(options.port)
    server.start(num_processes=1)
    app.start()


if __name__ == '__main__':
    runserver()
