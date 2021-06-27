from django.http import StreamingHttpResponse, JsonResponse
from simpleui.admin import AjaxAdmin
from django.contrib import admin
from import_export import resources
from StrategyModel.models import VulnStrategy
from import_export.admin import ImportExportModelAdmin
from ASE import settings
import logging
import os
import importlib
import json

logger = logging.getLogger("mdjango")


def update_from_server():
    pass


class VulnStrategyResource(resources.ModelResource):
    class Meta:
        model = VulnStrategy
        export_order = ('strategy_name', 'port', 'service_name', 'application', 'version', 'create_time')


class VulnStrategyAdmin(AjaxAdmin, ImportExportModelAdmin):
    list_display = ('strategy_name', 'port', 'service_name', 'application', 'version', 'create_time')  # list
    search_fields = ('strategy_name', 'port', 'service_name', 'application')
    list_filter = ('service_name', 'application', 'create_time')
    resource_class = VulnStrategyResource
    list_per_page = 10

    actions = ['update_poc']

    def changelist_view(self, request, extra_context=None):
        try:
            action = self.get_actions(request)[request.POST['action']][0]
            action_acts_on_all = action.acts_on_all
        except (KeyError, AttributeError):
            action_acts_on_all = False

        if action_acts_on_all:
            post = request.POST.copy()
            post.setlist(admin.helpers.ACTION_CHECKBOX_NAME,
                         self.model.objects.values_list('id', flat=True))
            request.POST = post

        return super(VulnStrategyAdmin, self).changelist_view(request, extra_context)

    def update_poc(self, request, queryset):

        old_strategies = []
        for s in VulnStrategy.objects.all().values():
            old_strategies.append(s['file'].replace(settings.STRATEGY_TOOLS_PATH, ''))

        logger.info('find {} old strategies'.format(len(old_strategies)))

        update_from_server()

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
                                               file=settings.STRATEGY_TOOLS_PATH + file_name)
                    save_result.save()
                    logger.info('add strategy: {}'.format(strategy_tool.readme))
                except Exception as e:
                    logger.error('code 0625001 - {}'.format(e))

    update_poc.short_description = ' update poc'
    # icon，https://fontawesome.com
    update_poc.icon = 'fa-solid fa-pen'
    # https://element.eleme.cn/#/zh-CN/component/button
    update_poc.type = 'success'
    update_poc.style = 'color:black;'
    update_poc.confirm = 'update poc ?'
    update_poc.acts_on_all = True


admin.site.register(VulnStrategy, VulnStrategyAdmin)