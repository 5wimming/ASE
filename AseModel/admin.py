import xlwt
from django.http import StreamingHttpResponse, JsonResponse
from simpleui.admin import AjaxAdmin
from django.contrib import admin
from import_export import resources
from AseModel.models import ScanPort, ScanVuln, ScanWeb
from import_export.admin import ImportExportModelAdmin


class ScanPortResource(resources.ModelResource):
    class Meta:
        model = ScanPort
        export_order = ('ip', 'domain', 'port', 'service_name', 'application', 'version', 'vendor')


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


class ScanVulnResource(resources.ModelResource):
    class Meta:
        model = ScanPort
        export_order = ('ip', 'domain', 'port', 'vuln_desc', 'scan_time', 'scan_task', 'strategy_id')


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


class ScanWebResource(resources.ModelResource):
    class Meta:
        model = ScanPort
        export_order = ("target", "port", "title", "headers", "body_size", "body_content", "application", "scan_time", "scan_engine", "scan_task", "strategy_id", "scan_node_id")


class ScanWebAdmin(AjaxAdmin, ImportExportModelAdmin):
    # readonly_fields = ("url", "target", "port", "status", "title", "headers", "body_size", "redirect_url", "body_content", "application", "scan_time", "scan_engine", "scan_task", "strategy_id", "scan_node_id")
    list_display = ("url", "title", "short_headers", "body_size", "application", "scan_task", "remarks", "scan_time")  # list
    search_fields = ("target", "port", "title", "headers", "body_content", "application", "scan_time", "scan_task")
    resource_class = ScanWebResource
    list_per_page = 20

    def has_add_permission(self, request):
        return False

    def has_import_permission(self, request):
        return False


admin.site.register(ScanVuln, ScanVulnAdmin)
admin.site.register(ScanPort, ScanPortAdmin)
admin.site.register(ScanWeb, ScanWebAdmin)
admin.site.site_title = "ASE"
admin.site.site_header = "Asset Scan Engine"
