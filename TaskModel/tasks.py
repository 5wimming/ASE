# -*- coding:utf-8 -*-
from __future__ import absolute_import, unicode_literals
from celery import shared_task
from django_redis import get_redis_connection
from AseModel.models import ScanPort, ScanVuln, ScanWeb
import logging
from StrategyModel.models import VulnStrategy, NvdCve
from TaskModel.models import IpTaskList
from ASE import settings
import time
import os
import IPy
import queue
import random
import urllib.parse
import threading
import importlib
import requests
from multiping import MultiPing
from ping3 import ping
from . import nmap_task
from . import web_crawler
from .masscan_task import IpMasscan
from .redis_task import RedisController
from bs4 import BeautifulSoup

logger = logging.getLogger("mdjango")


def fun_version(v1, v2):
    l_1 = v1.split('.')
    l_2 = v2.split('.')
    c = 0
    while True:
        try:
            if c == len(l_1) and c == len(l_2):
                return True
            if len(l_1) == c:
                l_1.append(0)
            if len(l_2) == c:
                l_2.append(0)
            if int(l_1[c]) > int(l_2[c]):
                return True
            elif int(l_1[c]) < int(l_2[c]):
                return False
            c += 1
        except Exception as e:
            return v1 >= v2


def get_nvd_vuln(vendor, application, version):
    if not version:
        return None
    try:
        nvd_cve_values = NvdCve.objects.filter(vendor__icontains=vendor).values('application',
                                                                                'version_start_including',
                                                                                'version_end_including',
                                                                                'mid_version', 'id')
    except Exception as e:
        logger.error('code 0703001 - {}'.format(e))
        return None

    for value in nvd_cve_values:
        is_vuln = False
        if value['application'] in application:
            if version == value['mid_version']:
                is_vuln = True
            elif not value['version_end_including'] and not value['version_start_including']:
                pass
            elif value['version_end_including'] and value['version_start_including']:
                if fun_version(version, value['version_end_including']) and fun_version(version,
                                                                                        value['version_end_including']):
                    is_vuln = True
            elif (not value['version_end_including']) and fun_version(value['version_start_including'], version):
                is_vuln = True
            elif fun_version(version, value['version_end_including']):
                is_vuln = True

        if is_vuln:
            value2 = NvdCve.objects.filter(pk=value['id']).values('cve_data_meta', 'base_score',
                                                                  'description_value', 'cpe23uri')[0]

            return {'cve_data_meta': application + ' - ' + value2['cve_data_meta'], 'base_score': value2['base_score'],
                    'description_value': value2['description_value'], 'cpe': value2['cpe23uri'],
                    'version_start_including': value['version_start_including'],
                    'version_end_including': value['version_end_including'], 'mid_version': value['mid_version']}
    return None


def thread_process_func(task_queue, result_queue, task_proto, strategies, vuln_queue, web_queue, conn_redis):
    while True:
        try:
            target = task_queue.get_nowait()
            ip = target[0]
            port = target[1]
            ip_port = '{}-{}'.format(ip, port)
        except queue.Empty:
            logger.info('{} Task done'.format(threading.current_thread().name))
            result_queue.put_nowait('Task done')
            vuln_queue.put_nowait('Task done')
            web_queue.put_nowait('Task done')
            break

        try:
            # 避免masscan在同一时刻运行，造成结果损失
            for i in range(10000):
                wait_time = int(conn_redis.get_mas_time())
                if wait_time < 1:
                    break
                time.sleep(wait_time + 1)

            logger.info('{} - [{}] - {}'.format(threading.current_thread().name, task_queue.qsize(), ip_port))
            my_scan = IpMasscan('--wait 3 --rate 8000')
            ip_ports = my_scan.port_scan(ip, port)
            logger.info('masscan result: {} -     {}'.format(threading.current_thread().name, ip_ports))
            for ip_port in ip_ports:
                result = nmap_task.main(ip_port, port_type=task_proto)
                if not result:
                    continue
                result_queue.put_nowait(result)
                vuln_poc_scan(ip_port, result, strategies, vuln_queue, web_queue)
        except Exception as e:
            logger.error('code 0626001 - {} - {}'.format(threading.current_thread().name, e))
            continue


def vuln_poc_scan(ip_port, result, strategies, vuln_queue, web_queue):
    ip, port = ip_port.split(':')
    service_names = result['service_name'].lower()
    url_info = {}
    if 'http' in service_names:
        url_info = web_crawler.main('https://' + ip_port + '/')
    if url_info:
        url_info['ip'] = ip
        url_info['port'] = port
        web_queue.put_nowait(url_info)
    target_info = {'ip': ip, 'port': port, 'service': result['service_name'],
                   'application': result['application'], 'url': url_info.get('url', '')}
    nvd_result = get_nvd_vuln(result['application'], result['application'], result['application'])
    if nvd_result:
        nvd_version = 'version: {} - {} - {} \n'.format(nvd_result['version_start_including'],
                                                        nvd_result['mid_version'],
                                                        nvd_result['version_end_including'])

        vuln_result = {'ip': ip, 'port': port, 'vuln_desc': nvd_result['cve_data_meta'],
                       'remarks': nvd_version + nvd_result['description_value'], 'strategy_id': '',
                       'cpe': nvd_result['cpe'], 'scan_type': 'nvd', "base_score": nvd_result['base_score']}
        vuln_queue.put_nowait(vuln_result)
    for s in strategies:
        try:
            strategy_flag = False
            # 下沉策略，表示不管是什么协议交由poc决策
            if 'all-poc' in s['service_name'] and service_names:
                strategy_flag = True
            elif any(item.lower() in service_names and item.strip() for item in s['service_name'].split(',')):
                strategy_flag = True
            elif any(item.lower() in service_names and item.strip() for item in s['application'].split(',')):
                strategy_flag = True
            elif port in s['port'].split(','):
                strategy_flag = True

            if strategy_flag:
                logger.info('{} - {}'.format(s['strategy_name'], ip_port))

                strategy_module = s['file'].strip().split('.')[0].replace('/', '.').replace('\\', '.')
                strategy_tool = importlib.import_module(strategy_module)

                tool_result = strategy_tool.main(target_info)

                if tool_result:
                    vuln_result = {'ip': ip, 'port': port, 'vuln_desc': s['strategy_name'], 'strategy_id': s['id'],
                                   'remarks': tool_result, 'cpe': s['cpe'], 'scan_type': 'poc',
                                   "base_score": s['base_score']}
                    vuln_queue.put_nowait(vuln_result)

        except Exception as e:
            logger.error('code 0620002 - {}'.format(e))


def thread_port_result(result_queue, task_threads_count, task_name, task_proto, task_num):
    logger.info('{} - ports start saving'.format(task_name))
    thread_done_total = 0
    result_total = 0
    while True:
        try:
            if thread_done_total >= task_threads_count:
                logger.info('{} - ports end saving'.format(task_name))
                break
            result = result_queue.get(timeout=3600)
            result_total += 1

            if result == 'Task done':
                thread_done_total += 1
                continue
            # doing something
            save_result = ScanPort(ip=result['ip'], port=result['port'], service_name=result['service_name'],
                                   application=result['application'], version=result['version'],
                                   vendor=result['vendor'],
                                   scan_task=task_name, cpe=result['cpe'], extra_info=result['extra_info'],
                                   remarks=result['remarks'], hostname=result['hostname'], proto=task_proto,
                                   state=result['state'])
            save_result.save()
        except queue.Empty as e:
            result_total += 1
            logging.error('{} --- {} --- {}'.format(e,
                                                    e.__traceback__.tb_lineno,
                                                    e.__traceback__.tb_frame.f_globals["__file__"]))
        except Exception as e:
            result_total += 1
            logging.error('{} --- {} --- {}'.format(e,
                                                    e.__traceback__.tb_lineno,
                                                    e.__traceback__.tb_frame.f_globals["__file__"]))


def thread_vuln_result(result_queue, task_threads_count, task_name, task_num):
    logger.info('{} - vulns start saving'.format(task_name))
    thread_done_total = 0
    result_total = 0
    while True:
        try:
            if thread_done_total >= task_threads_count:
                logger.info('{} - vuln end saving'.format(task_name))
                break
            result = result_queue.get(timeout=3600)
            result_total += 1

            if result == 'Task done':
                thread_done_total += 1
                continue

            save_result = ScanVuln(ip=result['ip'], port=result['port'], vuln_desc=result['vuln_desc'],
                                   strategy_id=result['strategy_id'], remarks=result['remarks'], cpe=result['cpe'],
                                   scan_task=task_name, base_score=result['base_score'],
                                   scan_type=result['scan_type'])
            save_result.save()
        except queue.Empty as e:
            thread_done_total += 1
            logging.error('{} --- {} --- {}'.format(e,
                                                    e.__traceback__.tb_lineno,
                                                    e.__traceback__.tb_frame.f_globals["__file__"]))
        except Exception as e:
            thread_done_total += 1
            logging.error('code 0620005 - {} - {}'.format(threading.current_thread().name, e))


def thread_web_info_result(result_queue, task_threads_count, task_name, task_num):
    logger.info('{} - web start saving'.format(task_name))
    thread_done_total = 0
    result_total = 0
    while True:
        try:
            if thread_done_total >= task_threads_count:
                logger.info('{} - vuln end saving'.format(task_name))
                break
            result = result_queue.get(timeout=3600)
            result_total += 1

            if result == 'Task done':
                thread_done_total += 1
                continue

            save_result = ScanWeb(url=result['url'], target=result['ip'], port=result['port'],
                                  status=result['status'],
                                  title=result['title'], headers=result['headers'],
                                  body_size=result['body_size'], body_content=result['body_content'],
                                  redirect_url=result['redirect_url'], application=result['application'],
                                  scan_task=task_name)
            save_result.save()
        except queue.Empty as e:
            thread_done_total += 1
            logging.error('{} --- {} --- {}'.format(e,
                                                    e.__traceback__.tb_lineno,
                                                    e.__traceback__.tb_frame.f_globals["__file__"]))
        except Exception as e:
            thread_done_total += 1
            logging.error('{} --- {} --- {}'.format(e,
                                                    e.__traceback__.tb_lineno,
                                                    e.__traceback__.tb_frame.f_globals["__file__"]))


def get_ip(ips):
    result = []
    try:
        result = IPy.IP(ips)
    except Exception as e:
        logger.error('code 0615001 - {}'.format(e))

        if '-' in ips:
            temp_ip = ips.split('-')
            try:
                sub_ip = temp_ip[0][0:temp_ip[0].rfind('.')]
                for ip in range(int(temp_ip[0].split('.')[-1]), int(temp_ip[-1].split('.')[-1]) + 1):
                    result.append(sub_ip + '.' + str(ip))
            except Exception as e:
                logger.error('code 0615002 - {} - {}'.format(e, e.__traceback__.tb_lineno))
    return result


@shared_task
def start_port_scan(task_query):
    """扫描任务开始

    开始ip端口的扫描任务

    Args:
        task_query: 单个扫描任务.

    Returns:
        无

    Raises:
        IOError: An error occurred accessing the bigtable.Table object.
    """
    queryset = IpTaskList.objects.filter(id=task_query['id'])
    strategies = []
    try:
        for s in queryset.filter(id=task_query['id']).first().ip_task_strategy_name.all().values():
            strategies.append(s)
        logger.info('{} get {} strategies'.format(task_query['task_name'], len(strategies)))
    except Exception as e:
        logger.error('code 0620001 - {}'.format(e))
    task_key = str(task_query['id'])
    conn_redis = RedisController(task_key)
    if conn_redis.get_status() == 'suspend' and conn_redis.get_time() == str(task_query['create_time']):
        conn_redis.set_status('running')
    else:
        conn_redis.init_conn('running', 0, task_query['create_time'])
    time.sleep(3)

    queryset.filter(id=task_query['id']).update(progress='survival detecting')

    task_port = get_port_list(task_query)
    task_ip = get_ip_list(queryset, task_query)

    task_port = list(set(task_port))
    task_ip = list(set(task_ip))
    task_ip = get_alive_ips(task_ip, conn_redis)
    random.shuffle(task_ip)

    area_ports, area_ips = get_ports_ips_area(task_port, task_ip)
    area_ports.sort()

    subtask_num = 0
    task_queue = queue.Queue()
    port_index = int(conn_redis.get_port())
    port_len = len(area_ports)
    logger.info('scan content: [{}] --- [{}]'.format(area_ips, area_ports))
    for i, port_value in enumerate(area_ports):
        if i < port_index:
            continue
        for ip_i in area_ips:
            subtask_num += 1
            task_queue.put_nowait((ip_i, port_value))
            if subtask_num == settings.SUBTASK_NUM:
                begin_scan(strategies, task_query, task_queue, conn_redis)
                logger.info('subtask [{}:{}] - finished'.format(ip_i, port_value))
                queryset.filter(id=task_query['id']).update(
                    progress='{:.1%} completed'.format(i / port_len * 0.5 + 0.5))
                time.sleep(0.5)
                subtask_num = 0
            conn_redis_status = conn_redis.get_status()
            conn_redis.set_port(i)
            if 'end' in conn_redis_status or 'suspend' in conn_redis_status:
                logger.info('port: [{}] - {}'.format(port_value, conn_redis_status))
                return

    if task_queue.qsize() > 0:
        begin_scan(strategies, task_query, task_queue, conn_redis)

    if 'suspend' not in conn_redis.get_status():
        queryset.filter(id=task_query['id']).update(status='finished')

    queryset.filter(id=task_query['id']).update(progress='')

    logger.info('{} - end running'.format(task_query['task_name']))


def get_alive_ips(task_ips, conn_redis):
    """获取存活ip

        获取存活ip

        Args:
            task_ips: ip数组.
            conn_redis: reids句柄

        Returns:
            存活ip列表
        """
    ping_ips = [task_ips[i:i+100] for i in range(0, len(task_ips), 100)]
    no_responses = []
    for ips in ping_ips:
        try:
            mp = MultiPing(ips)
            mp.send()
            response, no_response = mp.receive(2)
            no_responses += no_response
        except Exception as e:
            print(e)

    alive_ips = list(set(task_ips) - set(no_responses))

    logger.info('MultiPing alive ips: {}'.format(alive_ips))

    no_responses_ips = iter([no_responses[i:i+150] for i in range(0, len(no_responses), 150)])
    my_scan = IpMasscan('--wait 3 --rate 8000')

    for i in range(10000):
        wait_time = int(conn_redis.get_mas_time())
        if wait_time < 1:
            ips = next(no_responses_ips, 'none')
            if ips == 'none':
                break
            alive_ips += my_scan.ip_scan(ips)
        time.sleep(wait_time + 1)
    logger.info('MultiPing + masscan alive ips: {}'.format(alive_ips))
    return alive_ips


def get_ports_ips_area(task_port, task_ip):
    """ip和端口的区间数组

        ip和端口的区间数组

        Args:
            task_ip: ip数组.
            task_port: 扫描端口数组

        Returns:
            area_ports, area_ips
        """
    area_ips = []
    for i in range(0, len(task_ip), 70):
        s = task_ip[i:i + 70]
        area_ips.append(s)

    port_len = len(area_ips[0])

    area_ports = []
    task_port = list(map(int, task_port))
    task_port.sort()
    # masscan并发量1500比较合理
    port_len = int(1500 / port_len)

    for i in range(0, len(task_port), port_len):
        ps = task_port[i: i + port_len]
        if -5 < ps[-1] - ps[0] - len(ps) < 5:
            area_ports.append('{}-{}'.format(ps[0], ps[-1]))
        else:
            area_ports.append(','.join(list(map(str, ps))))

    return area_ports, area_ips


def get_ip_list(queryset, task_query):
    """获取最终需要扫描的ip列表

    获取最终需要扫描的ip列表

    Args:
        task_query: 单个扫描任务.
        queryset: 数据库句柄.

    Returns:
        端口列表

    """
    task_ip = []
    ips_text = task_query['ips_text']
    ips_file = task_query['ips_file']
    if ips_file:
        try:
            with open(os.path.join(settings.BASE_DIR, ips_file), 'r') as fr:
                ips_temp = fr.readlines()
            for ip in ips_temp:
                task_ip.append(ip.strip())
        except Exception as e:
            queryset.update(status='File parsing error')
            logger.error('code 0614 - {}'.format(e))
    ips_text = ips_text.replace('\r', ',').replace('\n', ',').replace(';', ',').replace(',,', ',')
    for ip in ips_text.split(','):
        if ip:
            if '-' in ip or '/' in ip:
                for ip_temp in get_ip(ip):
                    task_ip.append(str(ip_temp))
            else:
                task_ip.append(ip.strip())
    return task_ip


def get_port_list(task_query):
    """获取去端口列表

    获取去端口列表

    Args:
        task_query: 单个扫描任务.

    Returns:
        端口列表

    """
    task_port = []
    ports_str = task_query['port'].replace('\r', ',').replace('\n', ',').replace('\t', ',').replace(';', ',').replace(
        ',,', ',')
    ports = ports_str.split(',')
    for port in ports:
        if port:
            port_ab = port.split('-')
            port_len = len(port_ab)
            if port_len == 1:
                task_port.append(port_ab[0])
            if port_len == 2 and port_ab[1] != '':
                for j in range(int(port_ab[0]), int(port_ab[1])):
                    task_port.append(str(j))
                task_port.append(port_ab[1])
    return task_port


def begin_scan(strategies, task_query, task_queue, conn_redis):
    """多线程扫描任务

    多线程扫描任务

    Args:
        conn_redis: redis句柄
        task_query: 单个扫描任务.
        strategies: 扫描策略
        task_queue: 扫描队列

    Returns:
        无

    """
    task_proto = task_query['proto']
    task_threads_count = task_query['threads_count']

    task_key = str(task_query['id'])
    task_num = task_queue.qsize()

    result_queue = queue.Queue()
    vuln_queue = queue.Queue()
    web_queue = queue.Queue()
    thread_list = list()
    for x in range(task_threads_count):
        thread = threading.Thread(target=thread_process_func, args=(task_queue, result_queue, task_proto,
                                                                    strategies, vuln_queue, web_queue, conn_redis))
        thread.start()
        thread_list.append(thread)
    logger.info('{} - saving'.format(task_query['task_name']))
    port_result_thread = threading.Thread(target=thread_port_result, args=(result_queue, task_threads_count,
                                                                           task_query['task_name'], task_proto,
                                                                           task_num),
                                          name='port result thread')
    port_result_thread.start()
    vuln_result_thread = threading.Thread(target=thread_vuln_result, args=(vuln_queue, task_threads_count,
                                                                           task_query['task_name'], task_num),
                                          name='vuln result thread')
    vuln_result_thread.start()
    web_info_result_thread = threading.Thread(target=thread_web_info_result,
                                              args=(web_queue, task_threads_count,
                                                    task_query['task_name'], task_num),
                                              name='vuln result thread')
    web_info_result_thread.start()
    logger.info('{} - start running'.format(task_query['task_name']))
    for thread in thread_list:
        thread.join()
    time.sleep(3)
    port_result_thread.join()
    vuln_result_thread.join()
    web_info_result_thread.join()
