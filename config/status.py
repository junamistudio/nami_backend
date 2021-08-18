# -*- coding: utf-8 -*-


class Status(object):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


# 一般
success = Status(200, 'success')
failed = Status(400, 'failed')


class BaseException(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
        Exception.__init__(self, code, msg)


class RemoteCallFailed(BaseException):
    pass


class SysConfigException(BaseException):
    pass


class CustomException(BaseException):
    pass
