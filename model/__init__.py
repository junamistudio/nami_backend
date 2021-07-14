# -*- coding: utf-8 -*-
# Author: junami@126.com

from peewee import *

from lib.permission import Permission, UserNeed, RoleNeed, DeptNeed
from model.db import database


class TinyIntegerField(IntegerField):
    db_field = 'tinyint'


class ModelException404(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
        Exception.__init__(self, code, msg)


class BaseModel(Model):
    class Meta:
        database = database

    @classmethod
    def get_or_404(cls, *query, msg="No Model Instance", **filters):
        try:
            return cls.get(*query, **filters)
        except DoesNotExist:
            raise ModelException404(code=404, msg=msg)

    class Permissions(object):

        def __init__(self, obj):
            self.obj = obj

        @property
        def edit(self):
            needs = []
            if hasattr(self.obj, 'create_user'):
                needs.append(UserNeed(self.obj.create_user))
            if hasattr(self.obj, 'modify_user'):
                needs.append(UserNeed(self.obj.modify_user))
            if hasattr(self.obj, 'send_user'):
                needs.append(UserNeed(self.obj.send_user))

            return Permission(*needs) & Permission(RoleNeed('admin'))

        @property
        def delete(self):
            return Permission(RoleNeed('admin'))

    @property
    def perms(self):
        return self.Permissions(self)
