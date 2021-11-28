# -*- coding:utf-8 -*-
from django.contrib import admin
from django.http import StreamingHttpResponse, JsonResponse
from import_export import resources
from TaskModel.models import IpTaskList
from AseModel.models import ScanPort, ScanVuln, ScanWeb
from StrategyModel.models import VulnStrategy, NvdCve
from import_export.admin import ImportExportModelAdmin
from django import forms
import logging
from . import tasks
from .redis_task import RedisController


logger = logging.getLogger("mdjango")
scanning_task = {}


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
            if 'running' in i['status']:
                continue
            queryset.filter(id=i['id']).update(status='running')
            tasks.start_port_scan.delay(i)

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
