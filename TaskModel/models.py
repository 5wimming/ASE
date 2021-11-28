from django.db import models
from AseModel.fields import RestrictedFileField
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.html import format_html
from ASE import settings
import time
import re


def upload_to(instance, filename):
    # 后缀
    sub = filename.split('.')[-1]
    name = filename.split('.')[-2]
    t = time.strftime('%Y%m%d%H%M%S', time.localtime())
    return settings.IPS_FILE_PATH + '%s_%s.%s' % (name, t, sub)


def port_validator(value):
    port_re = re.compile('^[\d{1,5}|,|\-]+$')
    if not port_re.match(value):
        raise ValidationError(u'Format error')


def service_name_validator(value):
    service_name_re = re.compile('^[\w|,]+$')
    if not service_name_re.match(value):
        raise ValidationError(u'Format error')


def ips_text_validator(value):
    service_name_re = re.compile('^[\d|\,|\.|\r|\n|\-|\/|\w]+$')
    if not service_name_re.match(value):
        raise ValidationError(u'Format error')


def proto_validator(value):
    if value not in ['TCP', 'UDP']:
        raise ValidationError(u'Format error')


class IpTaskList(models.Model):
    task_name = models.CharField(max_length=1022)
    ips_text = models.TextField(validators=[ips_text_validator], null=True, blank=True,
                                help_text='eg: 10.10.10.10,10.2.2.2', verbose_name="target")
    ips_file = RestrictedFileField(upload_to=upload_to, max_length=1000,
                                   content_types=['text/plain', ],
                                   max_upload_size=5242880, null=True, blank=True)
    create_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    proto = models.CharField(validators=[proto_validator], max_length=255, default='TCP', null=True, blank=True, help_text='eg: TCP,UDP')  # 传输层协议
    port = models.CharField(max_length=2046, default='80,443', validators=[port_validator], help_text='eg: 80,22,1-33')
    threads_count = models.IntegerField(u'线程数', default=1, validators=[MinValueValidator(1), MaxValueValidator(100)])
    remarks = models.CharField(max_length=1022, null=True, blank=True)  # 备注
    status = models.CharField(max_length=255, default='not scanned', null=True, blank=True, editable=False)
    progress = models.CharField(max_length=255, default='', null=True, blank=True, editable=False)
    ip_task_strategy_name = models.ManyToManyField('StrategyModel.VulnStrategy', blank=True, verbose_name="strategy")

    def scan_status(self):
        if self.status == 'running':
            format_td = format_html('<span style="padding:2px;background-color:#409EFF;color:white">{}</span>'
                                    .format(self.progress))
        elif self.status == 'finished':
            format_td = format_html('<span style="padding:2px;background-color:green;color:black">finished</span>')
        elif self.status == 'suspend':
            format_td = format_html('<span style="padding:2px;background-color:red;color:white">Suspend</span>')
        elif self.status == 'not scanned':
            format_td = format_html('<span style="padding:2px;background-color:white;color:black">Not scanned</span>')
        elif self.status == 'failed':
            format_td = format_html('<span style="padding:2px;background-color:yellow;color:black">Failed</span>')
        else:
            format_td = format_html('<span style="padding:2px;background-color:red;color:black">{}</span>'
                                    .format(self.status))
        return format_td

    scan_status.short_description = "status"

    def short_port(self):
        if len(str(self.port)) > 20:
            return '{}...'.format(str(self.port)[0:20])
        else:
            return str(self.port)
    short_port.allow_tags = True
    short_port.short_description = "port"

    class Meta:
        verbose_name = 'Host Scan'
        verbose_name_plural = 'Host Scan'
