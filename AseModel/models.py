from django.db import models

from django.db import models
from .fields import RestrictedFileField
import time


class ScanPort(models.Model):
    ip = models.CharField(max_length=255, verbose_name="target")
    domain = models.CharField(max_length=1022, null=True, blank=True)
    port = models.CharField(max_length=255)
    service_name = models.CharField(max_length=255, null=True, blank=True)
    application = models.CharField(max_length=1022, null=True, blank=True)
    version = models.CharField(max_length=1022, null=True, blank=True)
    vendor = models.CharField(max_length=1022, null=True, blank=True)
    scan_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    scan_engine = models.CharField(max_length=255, null=True, blank=True)  # 扫描平台
    scan_task = models.CharField(max_length=255, null=True, blank=True)
    strategy_id = models.CharField(max_length=255, null=True, blank=True)  # 策略id
    scan_node_id = models.CharField(max_length=255, null=True, blank=True)  # 扫描器节点
    remarks = models.CharField(max_length=1022, null=True, blank=True)  # 备注
    cpe = models.CharField(max_length=1022, null=True, blank=True)
    state = models.CharField(max_length=255, null=True, blank=True)  # nmap状态
    extra_info = models.CharField(max_length=1022, null=True, blank=True)  # nmap额外信息
    hostname = models.CharField(max_length=255, null=True, blank=True)
    # process_name = models.CharField(max_length=255, null=True, blank=True)
    # process_path = models.CharField(max_length=1022, null=True, blank=True)
    # process_pid = models.CharField(max_length=255, null=True, blank=True)
    proto = models.CharField(max_length=255, null=True, blank=True)  # 传输层协议

    class Meta:
        verbose_name = 'port info'
        verbose_name_plural = 'port info'


def upload_to(instance, filename):
    # 后缀
    sub = filename.split('.')[-1]
    name = filename.split('.')[-2]
    t = time.strftime('%Y%m%d%H%M%S', time.localtime())
    return 'files/%s_%s.%s' % (name, t, sub)


class ScanVuln(models.Model):
    ip = models.CharField(max_length=255, verbose_name="target")
    domain = models.CharField(max_length=1022, null=True, blank=True)
    port = models.CharField(max_length=255, default=0)
    vuln_desc = models.CharField(max_length=1022, null=True, blank=True)
    scan_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    scan_engine = models.CharField(max_length=255, null=True, blank=True)  # 扫描平台
    scan_task = models.CharField(max_length=255, null=True, blank=True)
    strategy_id = models.CharField(max_length=255, null=True, blank=True)  # 策略id
    scan_node_id = models.CharField(max_length=255, null=True, blank=True)  # 扫描器节点
    remarks = models.CharField(max_length=1022, null=True, blank=True)  # 备注
    cpe = models.CharField(max_length=1022, null=True, blank=True)

    class Meta:
        verbose_name = 'vuln info'
        verbose_name_plural = 'vuln info'


class ScanWeb(models.Model):
    url = models.CharField(max_length=2046, null=True, blank=True)
    target = models.CharField(max_length=2046, null=True, blank=True)
    port = models.CharField(max_length=255, default=0)
    status = models.IntegerField(null=True, blank=True)
    title = models.CharField(max_length=1022, null=True, blank=True)
    headers = models.TextField(null=True, blank=True)
    body_size = models.IntegerField(null=True, blank=True)
    body_content = models.TextField(null=True, blank=True)
    redirect_url = models.CharField(max_length=1022, null=True, blank=True)
    application = models.CharField(max_length=1022, null=True, blank=True)
    scan_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    scan_engine = models.CharField(max_length=255, null=True, blank=True)  # 扫描平台
    scan_task = models.CharField(max_length=255, null=True, blank=True)
    strategy_id = models.CharField(max_length=255, null=True, blank=True)  # 策略id
    scan_node_id = models.CharField(max_length=255, null=True, blank=True)  # 扫描器节点
    remarks = models.CharField(max_length=1022, null=True, blank=True)  # 备注

    def short_headers(self):
        if len(str(self.headers)) > 20:
            return '{}...'.format(str(self.headers)[0:50])
        else:
            return str(self.headers)
    short_headers.allow_tags = True
    short_headers.short_description = "headers"

    class Meta:
        verbose_name = 'web info'
        verbose_name_plural = 'web info'
