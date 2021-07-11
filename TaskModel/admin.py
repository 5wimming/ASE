# -*- coding:utf-8 -*-
from django.contrib import admin
from django.http import StreamingHttpResponse, JsonResponse
from import_export import resources
from TaskModel.models import IpTaskList
from AseModel.models import ScanPort, ScanVuln, ScanWeb
from StrategyModel.models import VulnStrategy, NvdCve
from import_export.admin import ImportExportModelAdmin
from bs4 import BeautifulSoup
from django_redis import get_redis_connection
import urllib.parse
import threading
import queue
import random
from django import forms
import logging
import os
import time
from ASE import settings
from . import nmap_task
import StrategyTools
from django_redis import get_redis_connection
import importlib
import requests
import IPy
from .redis_task import RedisController

logger = logging.getLogger("mdjango")
scanning_task = {}


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
                logger.error('code 0615002 - {}'.format(e))
    return result


def get_url_info(url):
    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Ase/20160606 Firefox/60.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Cookie': 'rememberMe=ase',
        'X-Originating-IP': '127.0.0.1',
        'X-Client-IP': '127.0.0.1',
        'X-Forwarded-For': '127.0.0.1'
    }
    try:
        r = requests.get(url, headers=request_headers, timeout=2, verify=False)
        origin_title = ''

        try:
            soup = BeautifulSoup(r.content.decode("utf-8", "replace"), 'html.parser')
            origin_title = soup.title if soup.title else "none"
            origin_title = str(urllib.parse.unquote(origin_title, encoding='utf-8')).replace("\n", " ").replace("\r",
                                                                                                                " ") \
                .replace("\t", " ").replace("<title>", " ").replace("</title>", " ").strip()
        except Exception as e:
            logger.error('code 0627003 - {}'.format(e))

        headers = str(r.headers)

        result = {
            'url': url,
            'title': origin_title,
            'status': r.status_code,
            'headers': headers,
            'body_size': len(r.text),
            'body_content': r.text[0:5000],
            'application': 'shiro' if 'rememberMe=deleteMe' in headers else '',
            'redirect_url': r.url
        }
        return result
    except Exception as e:
        logger.error('code 0625005 - {}'.format(e))
    return {}


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


def thread_process_func(task_queue, result_queue, task_proto, task_key, strategies, vuln_queue,
                        web_queue, task_ip, task_port, conn_redis):
    for i_scan in range(65535000000):
        try:
            try:
                target = task_queue.get_nowait()
                ip = task_ip[target[0]]
                port = task_port[target[1]]
                ip_port = '{}:{}'.format(ip, port)
            except queue.Empty:
                logger.info('{} Task done'.format(threading.current_thread().name))
                result_queue.put_nowait('Task done')
                vuln_queue.put_nowait('Task done')
                web_queue.put_nowait('Task done')
                break

            if i_scan % 8 == 0:
                conn_redis_status = conn_redis.get_status()
                conn_redis.set_port(target[1])
                if 'end' in conn_redis_status or 'suspend' in conn_redis_status:
                    logger.info('{} - [{}] - {}'.format('end or suspend', task_queue.qsize(), ip_port))
                    result_queue.put_nowait('Task done')
                    vuln_queue.put_nowait('Task done')
                    web_queue.put_nowait('Task done')
                    break

            logger.info('{} - [{}] - {}'.format(threading.current_thread().name, task_queue.qsize(), ip_port))
            result = nmap_task.main(ip_port, port_type=task_proto)
            if result:
                result_queue.put_nowait(result)
            else:
                continue
        except Exception as e:
            logger.error('code 0626001 - {} - {}'.format(threading.current_thread().name, e))

        service_names = result['service_name'].lower()

        url_info = {}
        if 'http' in service_names:
            url_info = get_url_info('http://' + ip_port + '/')
            if not url_info:
                url_info = get_url_info('https://' + ip_port + '/')

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
                if any(item.lower() in service_names and item.strip() for item in s['service_name'].split(',')):
                    strategy_flag = True
                if any(item.lower() in service_names and item.strip() for item in s['application'].split(',')):
                    strategy_flag = True
                if port in s['port'].split(','):
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


def thread_port_result(result_queue, task_threads_count, task_name, task_proto, task_key):
    logger.info('{} - ports start saving'.format(task_name))
    thread_done_total = 0
    result_total = 0
    try:
        for i_scan in range(65535000000):
            try:
                result = result_queue.get()
                result_total += 1

                if result == 'Task done':
                    thread_done_total += 1
                    if thread_done_total == task_threads_count:
                        logger.info('{} - ports end saving'.format(task_name))
                        break
                    else:
                        continue
                # doing something
                save_result = ScanPort(ip=result['ip'], port=result['port'], service_name=result['service_name'],
                                       application=result['application'], version=result['version'],
                                       vendor=result['vendor'],
                                       scan_task=task_name, cpe=result['cpe'], extra_info=result['extra_info'],
                                       remarks=result['remarks'], hostname=result['hostname'], proto=task_proto,
                                       state=result['state'])
                save_result.save()
            except Exception as e:
                logging.error('code 0620003 - {} - {}'.format(threading.current_thread().name, e))
    except Exception as e:
        logging.error('code 0620004 - {} - {}'.format(threading.current_thread().name, e))


def thread_vuln_result(result_queue, task_threads_count, task_name, task_key):
    logger.info('{} - vulns start saving'.format(task_name))
    thread_done_total = 0
    result_total = 0
    try:

        for i_scan in range(65535000000):
            try:
                result = result_queue.get()
                result_total += 1

                if result == 'Task done':
                    thread_done_total += 1
                    if thread_done_total == task_threads_count:
                        logger.info('{} - vulns end saving'.format(task_name))
                        break
                    else:
                        continue
                # vuln_result = {'ip': ip, 'port': port, 'vuln_desc': s['strategy_name'], 'strategy_id': s['id'],
                #                                        'remarks': s['remarks'], 'cpe': s['cpe']}
                save_result = ScanVuln(ip=result['ip'], port=result['port'], vuln_desc=result['vuln_desc'],
                                       strategy_id=result['strategy_id'], remarks=result['remarks'], cpe=result['cpe'],
                                       scan_task=task_name, base_score=result['base_score'],
                                       scan_type=result['scan_type'])
                save_result.save()
            except Exception as e:
                logging.error('code 0620005 - {} - {}'.format(threading.current_thread().name, e))
    except Exception as e:
        logging.error('code 0620006 - {} - {}'.format(threading.current_thread().name, e))


def thread_web_info_result(result_queue, task_threads_count, task_name, task_key):
    logger.info('{} - web start saving'.format(task_name))
    thread_done_total = 0
    result_total = 0
    try:
        for i_scan in range(65535000000):
            try:
                result = result_queue.get()
                result_total += 1

                if result == 'Task done':
                    thread_done_total += 1
                    if thread_done_total == task_threads_count:
                        logger.info('{} - web end saving'.format(task_name))
                        break
                    else:
                        continue

                save_result = ScanWeb(url=result['url'], target=result['ip'], port=result['port'],
                                      status=result['status'],
                                      title=result['title'], headers=result['headers'],
                                      body_size=result['body_size'], body_content=result['body_content'],
                                      redirect_url=result['redirect_url'], application=result['application'],
                                      scan_task=task_name)
                save_result.save()
            except Exception as e:
                logging.error('code 0627005 - {} - {}'.format(threading.current_thread().name, e))
    except Exception as e:
        logging.error('code 0627006 - {} - {}'.format(threading.current_thread().name, e))


class IpTaskListResource(resources.ModelResource):
    class Meta:
        model = IpTaskList


class IpTaskListForm(forms.ModelForm):
    class Meta:
        model = IpTaskList
        fields = ('ips_text',)
        widgets = {
            'ips_text': forms.Textarea(attrs={'cols': 40, 'rows': 20}),
        }


class IpTaskListAdmin(ImportExportModelAdmin, forms.ModelForm):
    list_display = ('id', 'task_name', 'short_port', 'create_time', 'scan_status')  # list
    search_fields = ('id', 'task_name', 'port', 'create_time', 'status')
    fields = (
        'task_name', ('ips_text', 'ips_file'), 'proto', 'port', 'threads_count', 'ip_task_strategy_name', 'remarks')
    resource_class = IpTaskListResource
    ordering = ("-create_time",)
    form = IpTaskListForm
    filter_horizontal = ('ip_task_strategy_name',)

    # add buttons
    actions = ['start_scan', 'suspend_scan', 'end_scan']

    def start_scan(self, request, queryset):
        for i in queryset.values():

            strategies = []
            try:
                for s in queryset.filter(id=i['id']).first().ip_task_strategy_name.all().values():
                    strategies.append(s)
                logger.info('{} get {} strategies'.format(i['task_name'], len(strategies)))
            except Exception as e:
                logger.error('code 0620001 - {}'.format(e))

            if 'running' in i['status']:
                continue
            queryset.filter(id=i['id']).update(status='running')
            task_port = []
            ports = i['port'].replace('\r', ',').replace('\n', ',').replace(';', ',').replace(',,', ',').split(',')
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
            task_ip = []
            ips_text = i['ips_text']
            ips_file = i['ips_file']

            if ips_file:
                try:
                    with open(os.path.join(settings.BASE_DIR, ips_file), 'r') as fr:
                        ips_temp = fr.readlines()
                    for ip in ips_temp:
                        task_ip.append(ip.strip())
                except Exception as e:
                    queryset.update(status='File parsing error')
                    logger.error('code 0614 - {}'.format(e))
            ips_text = ips_text.replace('\r', ',').replace('\n', ',').replace(';', ',')

            for ip in ips_text.split(','):
                if ip:
                    if '-' in ip or '/' in ip:
                        for ip_temp in get_ip(ip):
                            task_ip.append(str(ip_temp))
                    else:
                        task_ip.append(ip.strip())

            task_proto = i['proto']
            task_threads_count = i['threads_count']
            task_ip = list(set(task_ip))
            random.shuffle(task_ip)
            task_port = list(set(task_port))
            task_port.sort()

            task_key = str(i['id'])
            conn_redis = RedisController(task_key)

            if conn_redis.get_status() == 'suspend' and conn_redis.get_time() == str(i['create_time']):
                conn_redis.set_status('running')
            else:
                conn_redis.init_conn('running', 0, i['create_time'])
            time.sleep(10)

            task_queue = queue.Queue()
            result_queue = queue.Queue()
            vuln_queue = queue.Queue()
            web_queue = queue.Queue()

            port_index = int(conn_redis.get_port())
            task_ip_nums = range(len(task_ip))
            for port_i in range(port_index, len(task_port)):
                for ip_i in task_ip_nums:
                    task_queue.put_nowait((ip_i, port_i))

            thread_list = list()
            for x in range(task_threads_count):
                thread = threading.Thread(target=thread_process_func, args=(task_queue, result_queue, task_proto,
                                                                            task_key, strategies, vuln_queue,
                                                                            web_queue, task_ip, task_port, conn_redis))
                thread.start()
                thread_list.append(thread)

            logger.info('{} - saving'.format(i['task_name']))
            port_result_thread = threading.Thread(target=thread_port_result, args=(result_queue, task_threads_count,
                                                                                   i['task_name'], task_proto,
                                                                                   task_key),
                                                  name='port result thread')
            port_result_thread.start()

            vuln_result_thread = threading.Thread(target=thread_vuln_result, args=(vuln_queue, task_threads_count,
                                                                                   i['task_name'], task_key),
                                                  name='vuln result thread')
            vuln_result_thread.start()

            web_info_result_thread = threading.Thread(target=thread_web_info_result,
                                                      args=(web_queue, task_threads_count,
                                                            i['task_name'], task_key),
                                                      name='vuln result thread')
            web_info_result_thread.start()

            logger.info('{} - start running'.format(i['task_name']))

            for thread in thread_list:
                thread.join()

            time.sleep(3)

            port_result_thread.join()
            vuln_result_thread.join()
            web_info_result_thread.join()

            if 'suspend' not in conn_redis.get_status():
                queryset.filter(id=i['id']).update(status='finished')

            logger.info('{} - end running'.format(i['task_name']))
            break

    start_scan.short_description = ' start scan'
    # icon，https://fontawesome.com
    start_scan.icon = 'far fa-play-circle'
    # https://element.eleme.cn/#/zh-CN/component/button
    start_scan.type = 'success'
    start_scan.style = 'color:black;'
    start_scan.confirm = 'start scan ?'

    def suspend_scan(self, request, queryset):
        for i in queryset.values():
            task_key = str(i['id'])
            conn_redis = RedisController(task_key)

            if 'finished' in i['status'] or 'not scanned' in i['status'] or 'suspend' in i['status']:
                continue

            if 'running' in conn_redis.get_status():
                conn_redis.set_status('suspend')
                conn_redis.set_time(i['create_time'])
            else:
                conn_redis.init_conn('end', 0, i['create_time'])

            queryset.filter(id=i['id']).update(status='suspend')

    suspend_scan.short_description = ' suspend scan'
    # icon，https://fontawesome.com
    suspend_scan.icon = 'fas fa-arrow-circle-right'
    # https://element.eleme.cn/#/zh-CN/component/button
    suspend_scan.type = 'success'
    suspend_scan.style = 'color:black;'
    suspend_scan.confirm = 'suspend scan ?'

    def end_scan(self, request, queryset):
        for i in queryset.values():
            task_key = str(i['id'])
            conn_redis = RedisController(task_key)
            if 'finished' in i['status'] or 'not scanned' in i['status']:
                continue

            conn_redis.init_conn('end', 0, i['create_time'])

            queryset.filter(id=i['id']).update(status='finished')

    end_scan.short_description = ' end scan'
    # icon，https://fontawesome.com
    end_scan.icon = 'far fa-stop-circle'
    # https://element.eleme.cn/#/zh-CN/component/button
    end_scan.type = 'success'
    end_scan.style = 'color:black;'
    end_scan.confirm = 'end scan ?'


admin.site.register(IpTaskList, IpTaskListAdmin)
