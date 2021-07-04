from django.http import StreamingHttpResponse, JsonResponse
from django.contrib import admin
from import_export import resources
from StrategyModel.models import VulnStrategy, NvdCve
from import_export.admin import ImportExportModelAdmin, ImportExportActionModelAdmin
from simpleui.admin import AjaxAdmin
from ASE import settings
import logging
import os
import importlib
import requests
import json
from . import update_cve

logger = logging.getLogger("mdjango")


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

        r = requests.get(git_url, headers=request_headers, verify=False, timeout=1000)
        git_json = json.loads(r.text)
        for git_info in git_json:
            if git_info['name'] not in local_file_names:
                try:
                    r_poc = requests.get(git_info['download_url'], headers=request_headers, verify=False, timeout=1000)
                    with open(tools_path + git_info['name'], "wb") as code:
                        code.write(r_poc.content)
                except Exception as e:
                    logger.error('0703010 - {}'.format(e))

    except Exception as e:
        logger.error('code 0703006 - {}'.format(e))
        return

    logger.info('download poc successful - {}'.format(git_url))


class VulnStrategyResource(resources.ModelResource):
    class Meta:
        model = VulnStrategy


def update_poc(git_url):
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
                                           cpe=readme['cpe'], remarks=readme['remarks'], base_score=readme['base_score'],
                                           file=settings.STRATEGY_TOOLS_PATH + file_name)
                save_result.save()
                logger.info('add strategy: {}'.format(strategy_tool.readme))
            except Exception as e:
                logger.error('code 0625001 - {}'.format(e))


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

        update_poc(git_url)

        return JsonResponse(data={
                'status': 'success',
                'msg': 'update success'
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


def update_cve_info(url):
    sql_values = NvdCve.objects.values('cve_data_meta', 'version_start_including', 'version_end_including',
                                       'mid_version')
    sql_dict = {}
    for sql_value in sql_values:
        sql_dict[sql_value['cve_data_meta'] + sql_value['version_start_including'] +
                 sql_value['version_end_including'] + sql_value['mid_version']] = 1

    update_cve.main(url, sql_dict)


class NvdCveAdmin(ImportExportActionModelAdmin, ImportExportModelAdmin, AjaxAdmin):
    list_display = ('application', 'vendor', 'cve_data_meta', 'base_score', 'version_start_including', 'version_end_including',
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
    update_nvd_status = False

    def layer_update_cve(self, request, queryset):
        nvd_url = request.POST['name']
        if not nvd_url.startswith('https://nvd.nist.gov/feeds/json/'):
            return JsonResponse(data={
                'status': 'error',
                'msg': 'nvd url is illegal'
            })

        if self.update_nvd_status:
            return JsonResponse(data={
                'status': 'success',
                'msg': 'Please wait a moment, updating now'
            })

        self.update_nvd_status = True

        try:
            update_cve_info(nvd_url)
        except Exception as e:
            logger.error('code 07020010 - {}'.format(e))
        finally:
            self.update_nvd_status = False

        return JsonResponse(data={
            'status': 'success',
            'msg': ' nvd update success'
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
        delete_flag = False
        if input_name == 'delete all':
            try:
                NvdCve.objects.all().delete()
                delete_flag = True
            except Exception as e:
                logger.error('code 0702011 - {}'.format(e))

        if delete_flag:
            logger.info('deleted all nvd data')
            return JsonResponse(data={
                'status': 'success',
                'msg': ' successfully deleted'
            })
        else:
            return JsonResponse(data={
                'status': 'error',
                'msg': ' delete error'
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