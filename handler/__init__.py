# -*- coding: utf-8 -*-
import datetime
import decimal
import hashlib
import json
import logging
import time
import traceback
from http.cookies import Morsel

import config
import re
from tornado.options import options
from concurrent.futures import ThreadPoolExecutor

import jsonschema
import peewee
from tornado.web import RequestHandler, Finish
import model

from lib.permission import (
    Identity, UserNeed, RoleNeed, DeptNeed, ItemNeed,
    AnonymousIdentity,
    PermissionDenied
)
from lib.redis_helper import RedisDB
from lib.util import Row
from model.models import (
    fn,
    JOIN
)

logger = logging.getLogger(__name__)

Morsel._reserved['samesite'] = 'SameSite'


class JsonParseError(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


class TokenInvalid(Exception):
    pass


class TokenExpire(Exception):
    pass


class PermissionMixIn(object):
    @property
    def identity(self):
        if not hasattr(self, "_identity"):
            self._identity = self.get_identity()
        return self._identity

    def get_identity(self):
        if not self.user:
            return AnonymousIdentity()

        identity = Identity(self.user.user_name)
        identity.provides.add(UserNeed(self.user.user_name))
        identity.provides.add(RoleNeed(self.user.role_name))
        identity.provides.add(DeptNeed(self.user.dept_id))
        if self.user.is_superuser:
            identity.provides.add(RoleNeed('admin'))

        for k, each in self.user_db_permissions.items():
            each = Row(each)
            for db in each.db:
                identity.provides.add(ItemNeed('db', db, each.auth))
        return identity


class DMSThreadPoolExecutor(ThreadPoolExecutor):

    def submit(self, fn, *args, **kwargs):
        return super(DMSThreadPoolExecutor, self).submit(fn, *args, **kwargs)

    def shutdown(self, **kwargs):
        super(DMSThreadPoolExecutor, self).shutdown(**kwargs)


class BaseHandler(RequestHandler):
    executor = DMSThreadPoolExecutor(max_workers=8)

    TOKEN_INVALID = -2
    TOKEN_EXPIRE = -1
    TOKEN_MISSING = 0

    # EXPIRE_IN_SECOND = 60
    EXPIRE_IN_SECOND = 3600 * 24 * 3

    def initialize(self, auth=None):
        self.user = Row()
        self.auth = auth
        self.conf = self.application.settings
        self.redis = RedisDB()

    @staticmethod
    def dump_json(data, pretty=False):
        def converter(o):
            if isinstance(o, datetime.date):
                return str(o)
            if isinstance(o, decimal.Decimal):
                return float(o)

        indent = None
        if pretty:
            indent = 2
        ret = json.dumps(data, default=converter, indent=indent, ensure_ascii=False)
        return ret

    def out(self, code=200, data=None, msg='', **kwargs):
        output = {
            'code': code,
            'message': msg
        }
        if data is not None:
            output.setdefault('data', data)
        if kwargs:
            output.update(kwargs)

        res = self.dump_json(output, pretty=True)
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.write(res)
        if code != 200:
            logger.warning(
                'RES [{user:<12}] {code} {method} {uri} {data}'.format(
                    code=code,
                    uri=self.request.uri,
                    method=self.request.method,
                    data=output,
                    user=self.user.user_name if self.user else ''
                )
            )

    def abort(self, code=200, data=None, msg='', **kwargs):
        self.out(code=code, data=data, msg=msg, **kwargs)
        raise Finish()

    def get_current_user(self):
        """Override to determine the current user from, e.g., a cookie.

        This method may not be a coroutine.
        """
        return None

    def cache_user(self, uid, uname, elapsed_seconds=0):
        redis_user_key = "users:{}-{}".format(uname, uid)
        expire_seconds = int(self.EXPIRE_IN_SECOND - elapsed_seconds)
        cached = None
        if not self.redis.hexists(redis_user_key, 'user'):
            user = SysUser.select(
                SysUser.id,
                SysUser.user_name,
                SysUser.name,
                SysUser.email,
                SysUser.emp_level,
                SysUser.dept_id,
                SysUser.group_id,
                SysUser.leader,
                SysUser.level_code,
                SysUser.role_name,
                SysUser.group_id,
                SysUser.mobile,
                SysUser.post_name,
                SysUser.user_type,
                SysUser.is_active,
                SysUser.is_superuser,
                SysUser.auth_group,
                SysUser.last_login_time,
                SysUser.gmt_created,
                SysUser.gmt_modified
            ).where(SysUser.id == uid).dicts()
            if user.exists():
                user_json = self.dump_json(user.get())
                self.redis.hset(redis_user_key, 'user', user_json)
                self.redis.expire(redis_user_key, expire_seconds)
                cached = Row(user.get())
        else:
            user_dict = self.redis.hget(redis_user_key, 'user')
            cached = Row(json.loads(user_dict))
        self.user = cached
        return cached

    def cache_user_db_permissions(self, uid, uname, elapsed_seconds=0, reload=False):
        redis_user_key = "users:{}-{}".format(uname, uid)
        expire_seconds = int(self.EXPIRE_IN_SECOND - elapsed_seconds)
        cached = None

        if not self.redis.exists(redis_user_key):
            return cached

        if reload and self.redis.hexists(redis_user_key, 'permission'):
            self.redis.hdel(redis_user_key, 'permission')

        if not self.redis.hexists(redis_user_key, 'permission'):
            query_sys_user_auth = (
                SysUserAuth.select(
                    SysUserAuth.auth,
                    SysAuth.auth_name,
                    SysUserAuth.user,
                    SysUserAuth.user_name,
                    fn.GROUP_CONCAT(SysUserAuth.db).alias('db')
                ).join(
                    SysAuth, JOIN.LEFT_OUTER,
                    on=(SysUserAuth.auth == SysAuth.id)
                ).where(
                    SysUserAuth.user_name == uname
                ).group_by(SysUserAuth.auth)
            ).dicts()
            auth_list = []
            for each in query_sys_user_auth:
                each['db'] = list(map(int, str(each['db']).split(',')))
                auth_list.append(each)

            user_auth_json = self.dump_json(auth_list)
            self.redis.hset(redis_user_key, 'permission', user_auth_json)
            self.redis.expire(redis_user_key, expire_seconds)
            cached = {each['auth']: each for each in auth_list if each.get('auth')}
        else:
            user_auth_dict = self.redis.hget(redis_user_key, 'permission')
            auth_list = json.loads(user_auth_dict)
            cached = {each['auth']: each for each in auth_list}
        return cached

    def clean_cache_user(self, uid, uname):
        redis_user_key = "users:{}-{}".format(uname, uid)
        self.redis.delete(redis_user_key)

    def on_close(self):
        self.finish()

    def on_finish(self):
        return super(BaseHandler, self).on_finish()

    @staticmethod
    def md5(text):
        result = hashlib.md5(text)
        return result.hexdigest()

    def get_request_data(self):
        content_type = self.request.headers.get('Content-Type')
        method = self.request.method
        chunk = {k: self.get_argument(k) for k in self.request.arguments}
        chunk['query'] = Row({k: self.get_query_argument(k) for k in self.request.query_arguments})

        if content_type and self.request.body:
            if 'application/x-www-form-urlencoded' in content_type or \
                    'multipart/form-data' in content_type:
                chunk['body'] = Row({k: self.get_body_argument(k) for k in self.request.body_arguments})
            elif 'application/json' in content_type:
                try:
                    chunk['json'] = json.loads(self.request.body)
                except ValueError:
                    raise JsonParseError(400, "Parse json failed")
        log_msg = re.sub(r'"password": .{5}', '"password": "*****', self.dump_json(chunk))
        logger.info(
            '[{user:<12}] REQ {handler} {method} {uri} {data}'.format(
                handler=self,
                uri=self.request.uri,
                method=method,
                data=log_msg,
                user=self.user.user_name if self.user else ''
            )
        )
        return Row(chunk)

    def prepare(self):
        if self.auth and self.request.method.upper() in ["POST", "GET", "PUT", "PATCH", "DELETE"]:
            current_user = self.get_current_user()
            self.user = current_user

            if options.access_role and not (self.user.is_superuser == 1 or self.user.role_name in options.access_role):
                self.abort(code=401, msg="Unauthorized")

        self.req = self.get_request_data()
        # self.req['uid'] = self.user.id

    def set_default_headers(self):
        default_headers = (
            "Accept",
            "Accept-Encoding",
            "Authorization",
            "Content-Type",
            "DNT",
            "Origin",
            "User-Agent",
            "X-CSRF-Token",
            "X-Requested-With",
            "X-Xsrftoken"
        )

        org = self.request.headers.get('Origin')

        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Access-Control-Allow-Headers", ", ".join(default_headers))
        self.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.set_header("Expires", -1)
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, PUT, PATCH, DELETE, OPTIONS')

    def options(self, *args, **kwargs):
        self.set_status(204)
        self.on_close()

    @property
    def now(self):
        return int(time.time())

    def write_error(self, status_code, **kwargs):

        if "exc_info" in kwargs:
            error_obj = kwargs["exc_info"][1]
            error_trace_list = traceback.format_exception(*kwargs.get("exc_info"), limit=5)
            status, message = None, ''
            if isinstance(error_obj, jsonschema.exceptions.ValidationError):
                status = 400
                message = str(error_obj)  # "Bad Request "
            elif isinstance(error_obj, JsonParseError):
                status = 400
                message = "Request JSON Parsing Failed "
            elif isinstance(error_obj, peewee.IntegrityError):
                status = 4000
                message = str(error_obj)
            elif isinstance(error_obj, peewee.DoesNotExist):
                status = 404
                message = "Does Not Exist"
            elif isinstance(error_obj, PermissionDenied):
                status = 403
                message = "权限不足, {}".format(str(error_obj))
            elif isinstance(error_obj, model.ModelException404):
                status = error_obj.code
                message = error_obj.msg
            elif isinstance(error_obj, TokenInvalid):
                status = 401
                message = "请登录"
            elif isinstance(error_obj, TokenExpire):
                status = 412
                message = "登陆过期，请重新登录"
            elif isinstance(error_obj, config.status.SysConfigException):
                status = error_obj.code
                message = error_obj.msg
            elif isinstance(error_obj, config.status.CustomException):
                status = error_obj.code
                message = error_obj.msg
            elif self.settings.get("serve_traceback"):
                logger.debug(str(error_trace_list))

            if status and message:
                self.set_status(200)
                self.out(code=status, msg=message)
            else:
                self.set_status(status_code)
                self.out(status_code, msg=self._reason)
        else:
            self.set_status(status_code)
            self.out(status_code, msg=self._reason)

    def _request_summary(self):
        return "%s %s (%s)" % (self.request.method, self.request.uri,
                               self.request.remote_ip)

    def log_exception(self, typ, value, tb):
        """Override to customize logging of uncaught exceptions."""
        is_exclude = isinstance(
            value, (
                TokenInvalid,
                jsonschema.exceptions.ValidationError,
                JsonParseError,
                PermissionDenied
            )
        )
        if is_exclude:
            logger.warning("{} {}".format(self._request_summary(), value))
        else:
            super(BaseHandler, self).log_exception(typ, value, tb)


class UserBaseHandler(BaseHandler):

    def data_received(self, chunk):
        pass

    def prepare(self):
        super(UserBaseHandler, self).prepare()
