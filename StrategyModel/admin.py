from django.http import StreamingHttpResponse, JsonResponse
from django.contrib import admin
from import_export import resources
from StrategyModel.models import VulnStrategy, NvdCve
from import_export.admin import ImportExportModelAdmin, ImportExportActionModelAdmin
from simpleui.admin import AjaxAdmin
from django_redis import get_redis_connection
from ASE import settings
import logging
from . import tasks

logger = logging.getLogger("mdjango")
conn_redis = get_redis_connection('default')


class VulnStrategyResource(resources.ModelResource):
    class Meta:
        model = VulnStrategy


class VulnStrategyAdmin(ImportExportActionModelAdmin, ImportExportModelAdmin, AjaxAdmin):
    list_display = ('strategy_name', 'port', 'service_name', 'application', 'version', 'create_time')  # list
    search_fields = ('strategy_name', 'port', 'service_name', 'application')
    list_filter = ('service_name', 'application', 'create_time')
    resource_class = VulnStrategyResource
    list_per_page = 20

    actions = ['layer_update_poc']

    def layer_update_poc(self, request, queryset):

        git_url = request.POST['name']
        if not git_url.startswith('https://api.github.com/repos'):
            return JsonResponse(data={
                'status': 'error',
                'msg': 'url is illegal'
            })
        if conn_redis.get('poc_update') == b'True':
            return JsonResponse(data={
                'status': 'success',
                'msg': 'Please wait a moment, updating...'
            })

        try:
            conn_redis.set('poc_update', 'True')
            conn_redis.expire('poc_update', 18000)
            tasks.task_update_poc.delay(git_url)
        except Exception as e:
            logger.error('code 07100001 - {}'.format(e))
            conn_redis.set('poc_update', 'False')

        return JsonResponse(data={
            'status': 'success',
            'msg': 'updating now'
        })

    layer_update_poc.short_description = 'update poc'
    layer_update_poc.type = 'success'
    layer_update_poc.icon = 'el-icon-s-promotion'

    layer_update_poc.layer = {

        'title': 'confirm',
        'tips': 'you can input the storage url of POC',
        'confirm_button': 'submit',
        'cancel_button': 'cancel',
        'width': '40%',
        'labelWidth': "80px",
        'params': [{
            'type': 'input',
            'key': 'name',
            'label': 'url',
            'value': 'https://api.github.com/repos/5wimming/ASE/contents/StrategyTools',
            'require': False
        }]
    }


class NvdCveAdmin(ImportExportActionModelAdmin, ImportExportModelAdmin, AjaxAdmin):
    list_display = (
        'application', 'vendor', 'cve_data_meta', 'base_score', 'version_start_including', 'version_end_including',
        'mid_version')  # list
    search_fields = ('application', 'cve_data_meta', 'cpe23uri', 'version_start_including', 'version_end_including',
                     'mid_version')
    list_filter = ('base_score',)
    list_per_page = 20

    def has_add_permission(self, request):
        return False

    def has_export_permission(self, request):
        return False

    actions = ['layer_update_cve', 'delete_all_cve']

    def layer_update_cve(self, request, queryset):

        nvd_url = request.POST['name']
        if not nvd_url.startswith('https://nvd.nist.gov/feeds/json/'):
            return JsonResponse(data={
                'status': 'error',
                'msg': 'nvd url is illegal'
            })

        if conn_redis.get('nvd_update') == b'True':
            return JsonResponse(data={
                'status': 'success',
                'msg': 'Please wait a moment, updating...'
            })

        conn_redis.set('nvd_update', 'True')
        conn_redis.expire('nvd_update', 18000)
        try:
            tasks.task_update_cve_info.delay(nvd_url)
        except Exception as e:
            logger.error('code 0725006 - {}'.format(e))
            conn_redis.set('nvd_update', 'False')

        return JsonResponse(data={
            'status': 'success',
            'msg': ' nvd updating now'
        })

    layer_update_cve.short_description = 'update poc'
    layer_update_cve.type = 'success'
    layer_update_cve.icon = 'el-icon-s-promotion'

    layer_update_cve.layer = {
        'title': 'confirm',
        'tips': 'you can input the storage url of nvd',
        'confirm_button': 'submit',
        'cancel_button': 'cancel',
        'width': '40%',
        'labelWidth': "80px",
        'params': [{
            'type': 'input',
            'key': 'name',
            'label': 'url',
            'value': 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip',
            'require': False
        }]
    }

    def delete_all_cve(self, request, queryset):
        input_name = request.POST['name']
        if input_name != 'delete all':
            return JsonResponse(data={
                'status': 'error',
                'msg': ' input illegal'
            })

        if conn_redis.get('delete_all') != b'True':
            tasks.task_delete_cve.delay()

        return JsonResponse(data={
            'status': 'success',
            'msg': ' deleting now'
        })

    delete_all_cve.short_description = 'delete all'
    delete_all_cve.type = 'update'
    delete_all_cve.icon = 'el-icon-delete-solid'

    delete_all_cve.layer = {
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


admin.site.register(VulnStrategy, VulnStrategyAdmin)
admin.site.register(NvdCve, NvdCveAdmin)
