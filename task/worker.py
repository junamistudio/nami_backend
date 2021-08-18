from __future__ import absolute_import

from celery import Celery
from celery import Task
from celery import shared_task
from celery.utils.log import get_task_logger

import setting
from lib.redis_helper import RedisDB

from task.serializer import celery_dumps, celery_loads
from kombu.serialization import register
from redlock import RedLockFactory

register('custom', celery_dumps, celery_loads, content_type='application/x-custom-json', content_encoding='utf-8')
logger = get_task_logger(__name__)

celery_app = Celery(
    "tiny_task",
    broker="amqp://{user}:{passwd}@{addr}:{port}{vhost}".format(
        addr=setting.DEFAULT_MQ_ADDR,
        user=setting.DEFAULT_MQ_USER,
        passwd=setting.DEFAULT_MQ_PWD,
        port=setting.DEFAULT_MQ_PORT,
        vhost='/DMS_HOST'
    ),
    backend="redis://root:{passwd}@{addr}:{port}/3".format(
        addr=setting.REDIS_HOST,
        user='root',
        passwd=setting.REDIS_PASSWD,
        port=setting.REDIS_PORT
    ),
    include=[
        "handler.demo",
        "biz.send_mail",
        "handler.apply_exp",
        "handler.apply_dml",
        "handler.apply_syncdb",
        "task.schedule.cron_aliyun",
        "task.db_task.sync_schema",
        "task.sql_review_task.sql_review",
        "handler.apply_syncdb_deploy",
        "handler.apply_sql_audit_common",
        "handler.equ_host_task",
        "handler.equ_domain_task",
        "handler.base_database_task",
        "task.schedule.cron_monitor",
        "task.schedule.cron_cleaner",
        "handler.equ_instance_task",
    ],
)

redis_lock = RedLockFactory(
    connection_details=[
        {'host': setting.REDIS_HOST, 'password': setting.REDIS_PASSWD, 'port': setting.REDIS_PORT, 'db': 3}
    ]
)

celery_app.conf.update(
    CELERY_ENABLE_UTC=False,
    CELERY_TIMEZONE="Asia/Shanghai",
    CELERY_TASK_SERIALIZER="json",
    CELERY_RESULT_SERIALIZER="json",
    # CELERY_ACKS_LATE=True,
    CELERYD_PREFETCH_MULTIPLIER=1,
    CELERY_TASK_ANNOTATIONS={'*': {'rate_limit': '3/s'}},
    CELERY_ACCEPT_CONTENT=["json", "pickle"],
)
# schedule e.g: timedelta(seconds=1800), crontab(hour=23, minute=30, day_of_week='sunday'), crontab(minute="30,59")
celery_schedule = {
    # 'monitor_status': {
    #     'task': 'task.schedule.xxx',
    #     'schedule': crontab(minute="30,59"),
    #     'options': {'queue': 'schedule', 'expire_seconds': 900}
    # }
}

celery_app.conf.update(
    CELERYBEAT_SCHEDULE=celery_schedule,
    CELERYBEAT_SCHEDULER='task.scheduler.schedulers:DatabaseScheduler'
)


@celery_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    pass


class BaseTask(Task):
    _redis = None
    _database = None

    def __init__(self, *args, **kwargs):
        super(BaseTask, self).__init__(*args, **kwargs)

    @property
    def redis(self):
        if self._redis is None:
            self._redis = RedisDB({
                'REDIS_HOST': setting.REDIS_HOST,
                'REDIS_PORT': int(setting.REDIS_PORT),
                'REDIS_DB': int(setting.REDIS_DB),
                'REDIS_PASSWD': setting.REDIS_PASSWD
            })
        return self._redis

    def on_success(self, retval, task_id, args, kwargs):
        return super(BaseTask, self).on_success(retval, task_id, args, kwargs)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        return super(BaseTask, self).on_failure(exc, task_id, args, kwargs, einfo)

    def __call__(self, *args, **kwargs):
        return Task.__call__(self, *args, **kwargs)

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        return super(BaseTask, self).after_return(status, retval, task_id, args, kwargs, einfo)


@shared_task
def dms_test_add(x, y):
    return x + y
