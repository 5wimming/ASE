import xlwt
from django.http import StreamingHttpResponse, JsonResponse
from django.contrib import admin
from import_export import resources
from AseModel.models import ScanPort, ScanVuln, ScanWeb
from import_export.admin import ImportExportModelAdmin, ExportMixin
from django_redis import get_redis_connection
from simpleui.admin import AjaxAdmin
import logging
import time
from . import tasks

logger = logging.getLogger("mdjango")
conn_redis = get_redis_connection('default')


class ScanPortResource(resources.ModelResource):
    class Meta:
        model = ScanPort


class ScanPortAdmin(ImportExportModelAdmin, AjaxAdmin):
    readonly_fields = ["ip", "domain", "port", "service_name", "application", "version", "vendor", "scan_time", "proto", "scan_engine", "scan_task", "strategy_id", "scan_node_id", "cpe", "state", "extra_info", "hostname"]
    list_display = ('ip', 'port', 'service_name', 'application', 'version', 'remarks', 'scan_time')  # list
    search_fields = ('ip', 'port', 'service_name', 'application', 'remarks')
    resource_class = ScanPortResource
    list_per_page = 20

    # 关闭按钮
    def has_add_permission(self, request):
        return False

    def has_import_permission(self, request):
        return False

    actions = ['delete_all_ports']

    def delete_all_ports(self, request, queryset):
        input_name = request.POST['name']
        if input_name != 'delete all':
            return JsonResponse(data={
                'status': 'error',
                'msg': ' input illegal'
            })

        tasks.delete_ports_result.delay()

        return JsonResponse(data={
            'status': 'success',
            'msg': ' deleting now'
        })

    delete_all_ports.short_description = 'delete all'
    delete_all_ports.type = 'update'
    delete_all_ports.icon = 'el-icon-delete-solid'

    delete_all_ports.layer = {
        'title': 'confirm',
        'tips': 'please input "delete all"',
        'confirm_button': 'submit',
        'cancel_button': 'cancel',
        'width': '40%',
        'labelWidth': "80px",
        'params': [{
            'type': 'input',
            'key': 'name',
            'label': 'input',
            'require': True
        }]
    }


class ScanVulnResource(resources.ModelResource):
    class Meta:
        model = ScanVuln


class ScanVulnAdmin(ImportExportModelAdmin, AjaxAdmin):
    list_display = ('ip', 'port', 'vuln_desc', 'base_score', 'scan_task', 'scan_type', 'scan_time')  # list
    search_fields = ('ip', 'domain', 'port', 'vuln_desc', 'scan_time', 'scan_task')
    list_filter = ('scan_type',)
    resource_class = ScanVulnResource
    list_per_page = 20

    def has_add_permission(self, request):
        return False

    def has_import_permission(self, request):
        return False

    actions = ['delete_all_vulns']

    def delete_all_vulns(self, request, queryset):
        input_name = request.POST['name']
        if input_name != 'delete all':
            return JsonResponse(data={
                'status': 'error',
                'msg': ' input illegal'
            })

        logger.info('begin deleting vulns')

        tasks.delete_vuln_result.delay()

        return JsonResponse(data={
            'status': 'success',
            'msg': ' deleting now'
        })

    delete_all_vulns.short_description = 'delete all'
    delete_all_vulns.type = 'update'
    delete_all_vulns.icon = 'el-icon-delete-solid'

    delete_all_vulns.layer = {
        'title': 'confirm',
        'tips': 'please input "delete all"',
        'confirm_button': 'submit',
        'cancel_button': 'cancel',
        'width': '40%',
        'labelWidth': "80px",
        'params': [{
            'type': 'input',
            'key': 'name',
            'label': 'input',
            'require': True
        }]
    }


class ScanWebResource(resources.ModelResource):
    class Meta:
        model = ScanPort


class ScanWebAdmin(ImportExportModelAdmin, AjaxAdmin):
    list_display = ("url", "title", "short_headers", "body_size", "status", "scan_task", "remarks", "scan_time")  # list
    search_fields = ("target", "port", "title", "headers", "body_content", "application", "scan_time", "scan_task")
    resource_class = ScanWebResource
    list_per_page = 20

    def has_add_permission(self, request):
        return False

    def has_import_permission(self, request):
        return False

    actions = ['delete_all_webs']

    def delete_all_webs(self, request, queryset):
        input_name = request.POST['name']
        if input_name != 'delete all':
            return JsonResponse(data={
                'status': 'error',
                'msg': ' input illegal'
            })

        tasks.delete_web_result.delay()

        return JsonResponse(data={
            'status': 'success',
            'msg': ' deleting now'
        })

    delete_all_webs.short_description = 'delete all'
    delete_all_webs.type = 'update'
    delete_all_webs.icon = 'el-icon-delete-solid'

    delete_all_webs.layer = {
        'title': 'confirm',
        'tips': 'please input "delete all"',
        'confirm_button': 'submit',
        'cancel_button': 'cancel',
        'width': '40%',
        'labelWidth': "80px",
        'params': [{
            'type': 'input',
            'key': 'name',
            'label': 'input',
            'require': True
        }]
    }


admin.site.register(ScanVuln, ScanVulnAdmin)
admin.site.register(ScanPort, ScanPortAdmin)
admin.site.register(ScanWeb, ScanWebAdmin)
admin.site.site_title = "ASE"
admin.site.site_header = "Asset Scan Engine"
