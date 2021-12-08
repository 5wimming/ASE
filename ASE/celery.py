# coding:utf-8
from __future__ import absolute_import, unicode_literals
import os
from celery import Celery, platforms
from django.conf import settings

# set the default Django settings module for the 'celery' program.

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ASE.settings')

app = Celery('ASE', backend='redis://127.0.0.1:6379/0',  broker='redis://127.0.0.1:6379/0')  # amqp://asemq:Ase.mq.005 @127.0.0.1:5672/ase

# 指定从django的settings.py里读取celery配置
app.config_from_object('django.conf:settings')

# 自动从所有已注册的django app中加载任务
app.autodiscover_tasks()


# 用于测试的异步任务
@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))