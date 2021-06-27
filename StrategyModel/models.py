from django.db import models
from AseModel.fields import RestrictedFileField
from django.core.exceptions import ValidationError
import time
import re
from ASE import settings


def upload_to(instance, filename):
    sub = filename.split('.')[-1]
    name = filename.split('.')[-2]
    t = time.strftime('%Y%m%d%H%M%S', time.localtime())
    return settings.STRATEGY_TOOLS_PATH + 'poc_%s.%s' % (t, sub)


def port_validator(value):
    port_re = re.compile('^[\d{1,5}|,]+$')
    if not port_re.match(value):
        raise ValidationError(u'Format error')


def service_name_validator(value):
    service_name_re = re.compile('^[\w|_|,]+$')
    if not service_name_re.match(value):
        raise ValidationError(u'Format error')


class VulnStrategy(models.Model):
    strategy_name = models.CharField(max_length=1022)
    service_name = models.CharField(max_length=255, null=True, blank=True, validators=[service_name_validator], help_text='eg: https,http')
    create_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    port = models.CharField(max_length=255, default='1', validators=[port_validator], help_text='eg: 80,8080')
    application = models.CharField(max_length=1022, null=True, blank=True)
    version = models.CharField(max_length=1022, null=True, blank=True)
    vendor = models.CharField(max_length=1022, null=True, blank=True)
    cpe = models.CharField(max_length=1022, null=True, blank=True)
    remarks = models.CharField(max_length=1022, null=True, blank=True)  # 备注
    proto = models.CharField(max_length=255, null=True, blank=True)  # 传输层协议
    file = RestrictedFileField(upload_to=upload_to, max_length=100,
                               content_types=['text/x-python-script', ],
                               max_upload_size=5242880, null=True, blank=True)

    class Meta:
        verbose_name = 'Vuln Strategy'
        verbose_name_plural = 'Vuln Strategy'

    def __str__(self):
        return self.strategy_name


