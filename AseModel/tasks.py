# -*- encoding: utf-8 -*-
"""
@File    : tasks.py
@Time    : 2021/12/19 下午3:59
@Author  : 5wimming
"""
from __future__ import absolute_import, unicode_literals
from celery import shared_task
from AseModel.models import ScanPort, ScanVuln, ScanWeb
from django_redis import get_redis_connection
import logging

logger = logging.getLogger("mdjango")
conn_redis = get_redis_connection('default')


@shared_task
def delete_ports_result():
    try:
        ScanPort.objects.all().delete()
        logger.info('delete ports successful')
    except Exception as e:
        logger.error('delete ports error: {} --- {} --- {}'.format(e,
                                                                   e.__traceback__.tb_lineno,
                                                                   e.__traceback__.tb_frame.f_globals["__file__"]))


@shared_task
def delete_vuln_result():
    try:
        ScanVuln.objects.all().delete()
        logger.info('delete vuln successful')
    except Exception as e:
        logger.error('delete vuln error: {} --- {} --- {}'.format(e,
                                                                   e.__traceback__.tb_lineno,
                                                                   e.__traceback__.tb_frame.f_globals["__file__"]))


@shared_task
def delete_web_result():
    try:
        ScanWeb.objects.all().delete()
        logger.info('delete web successful')
    except Exception as e:
        logger.error('delete web error: {} --- {} --- {}'.format(e,
                                                                   e.__traceback__.tb_lineno,
                                                                   e.__traceback__.tb_frame.f_globals["__file__"]))