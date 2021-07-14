# -*- coding: utf-8 -*-


class Status(object):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


# 一般
success = Status(200, 'success')
failed = Status(400, 'failed')

confirm = Status(700, 'confirm')

# 具体业务
exist = Status(4000, u'资源已存在')
auth_failed = Status(4003, u'认证错误')
not_found = Status(4004, u'无记录')
arguments_error = Status(4005, u'参数错误')
not_activate = Status(4006, u'首次登陆请修改密码激活账户')

json_parse_error = Status(4008, u'JSON 格式错误')
pwd_not_set = Status(4009, u'passwd not set')
dissatisfy_precondition = Status(4012, u"不满足前提条件")
app_cfg_error = Status(5000, u"系统配置有误")

inception_error = Status(5101, u"系统配置有误")

# 结构设计 6000 <= code < 7000
ddl_schema_parse_failed = Status(6101, '无法解析建表语句')
ddl_db_not_found_dev = Status(6201, '未找到开发库')
ddl_db_unpaired = Status(6202, '存在多个线上线下库未配对')
ddl_table_locked = Status(6301, '当前表被占用')
ddl_table_duplicate = Status(6302, '重名表名称')
ddl_table_already_exists = Status(6303, '已在工单编辑中')
ddl_table_not_delete = Status(6304, "线上数据表不能被删除")
ddl_execute_sql_empty = Status(6404, "生成执行SQL为空")
ddl_not_allow_action = Status(6405, "当前状态无法进行此操作")
ddl_rule_check_not_pass = Status(6500, "规则校验未通过")

# 库表同步 7000 <= code < 8000


class RemoteCallFailed(Exception):
    pass


class SysConfigException(Exception):

    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
        Exception.__init__(self, code, msg)

class CustomException(Exception):

    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
        Exception.__init__(self, code, msg)