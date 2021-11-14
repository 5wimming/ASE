# -*- coding:utf-8 -*-
from __future__ import absolute_import, unicode_literals
from celery import shared_task
from StrategyModel.models import VulnStrategy, NvdCve
from django_redis import get_redis_connection
import logging
from . import update_cve
from ASE import settings
import os
import importlib
import requests
import json


logger = logging.getLogger("mdjango")
conn_redis = get_redis_connection('default')


@shared_task
def task_delete_cve():
    try:
        conn_redis.set('nvd_update', 'False')
        conn_redis.expire('nvd_update', 1800)
        conn_redis.set('poc_update', 'False')
        conn_redis.expire('poc_update', 1800)
        conn_redis.set('delete_all', 'True')
        conn_redis.expire('delete_all', 18000)
        NvdCve.objects.all().delete()
        logger.info('deleted cve data success')
    except Exception as e:
        logger.error('code 0725025 - {}'.format(e))
    finally:
        conn_redis.set('delete_all', 'False')


@shared_task
def task_update_cve_info(url):
    sql_values = NvdCve.objects.values('cve_data_meta', 'version_start_including', 'version_end_including',
                                       'mid_version')
    sql_dict = {}
    for sql_value in sql_values:
        sql_dict[sql_value['cve_data_meta'] + sql_value['version_start_including'] +
                 sql_value['version_end_including'] + sql_value['mid_version']] = 1
    try:
        update_cve.main(url, sql_dict)
    except Exception as e:
        logger.error('code 0725001 - {}'.format(e))
    finally:
        conn_redis.set('nvd_update', 'False')


@shared_task
def update_from_server(git_url):
    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Ase/20160606 Firefox/60.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    tools_path = os.path.join(settings.BASE_DIR, settings.STRATEGY_TOOLS_PATH)
    try:
        local_file_names = []
        for file_name in os.listdir(tools_path):
            local_file_names.append(file_name.strip())

        r = requests.get(git_url, headers=request_headers, verify=False, timeout=100)
        git_json = json.loads(r.text)
        for git_info in git_json:
            if git_info['name'] not in local_file_names:
                try:
                    r_poc = requests.get(git_info['download_url'], headers=request_headers, verify=False, timeout=100)
                    with open(tools_path + git_info['name'], "wb") as code:
                        code.write(r_poc.content)
                except Exception as e:
                    logger.error('0703010 - {}'.format(e))

    except Exception as e:
        logger.error('code 0703006 - {}'.format(e))
        return

    logger.info('download poc successful - {}'.format(git_url))


@shared_task
def task_update_poc(git_url):
    try:
        old_strategies = []
        for s in VulnStrategy.objects.all().values():
            old_strategies.append(s['file'].replace(settings.STRATEGY_TOOLS_PATH, ''))

        logger.info('find {} old strategies'.format(len(old_strategies)))

        update_from_server(git_url)

        for file_name in os.listdir(os.path.join(settings.BASE_DIR, settings.STRATEGY_TOOLS_PATH)):
            if file_name not in old_strategies and file_name.endswith('.py') and '__init__' not in file_name:
                print(file_name)
                try:

                    strategy_tool = importlib.import_module(settings.STRATEGY_TOOLS_PATH.replace('/', '.') +
                                                            file_name.replace('.py', ''))

                    readme = strategy_tool.readme
                    save_result = VulnStrategy(strategy_name=readme['strategy_name'], service_name=readme['service_name'],
                                               port=readme['port'], application=readme['application'],
                                               version=readme['version'], proto=readme['proto'], vendor=readme['vendor'],
                                               cpe=readme['cpe'], remarks=readme['remarks'],
                                               base_score=readme['base_score'],
                                               file=settings.STRATEGY_TOOLS_PATH + file_name)
                    save_result.save()
                    logger.info('add strategy: {}'.format(strategy_tool.readme))
                except Exception as e:
                    logger.error('code 0625001 - {}'.format(e))
    except Exception as e:
        logger.error('code 0725003 - {}'.format(e))
    finally:
        conn_redis.set('poc_update', 'False')
