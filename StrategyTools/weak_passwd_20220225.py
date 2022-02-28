# -*- encoding: utf-8 -*-
"""
@File    : weak_passwd_20220225.py
@Time    : 2022/2/17 下午5:00
@Author  : raoyongming
"""

import os
import subprocess
import sys
import time
import logging
from ASE import settings

logger = logging.getLogger("mdjango")

readme = {'strategy_name': 'weak passwd', 'service_name': 'all-poc',
          'port': '', 'application': 'weak passwd', 'proto': 'tcp', 'version': '',
          'remarks': '', 'cpe': '', 'vendor': '', 'base_score': '9'}

NAME_MAP = {"ms-sql-s": "mssql",
            "shell": "rsh",
            "exec": "rexec",
            "login": "rlogin",
            "snmptrap": "snmp"}


def start_scan(ip, port, ser, info_path):
    user_path = '{}user'.format(info_path)
    passwd_path = '{}password'.format(info_path)
    p = subprocess.Popen(
        ['hydra', '-L', user_path, '-P', passwd_path, '-s', port,
         '-t', '6', '-w', '8', '-W', '2', '-f', ip, ser],
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=-1)

    for line in p.stdout:
        line = line.strip()
        sys.stdout.flush()
        time.sleep(0.0001)
        if 'host' in line and 'password' in line:
            return line

    return None


def main(target_info, *args):
    ip = target_info.get('ip', '')
    port = target_info.get('port', '')
    service = target_info.get('service', '')
    result = None
    services = ['asterisk', 'afp', 'cisco-aaa', 'cisco-auth', 'cisco-enable', 'cvs', 'firebird', 'ftp',
                'http-form-get', 'http-form-post', 'http-get', 'http-head', 'http-post', 'http-proxy',
                'https-form-get', 'https-form-post', 'https-get', 'https-head', 'https-post', 'icq',
                'imap', 'irc', 'ldap', 'memcached', 'mongodb', 'ms-sql', 'mysql', 'ncp', 'nntp',
                'oracle-listener', 'oracle-sid', 'oracle', 'pc-anywhere', 'pcnfs', 'pop3', 'postgres',
                'radmin', 'rdp', 'rexec', 'rlogin', 'rsh', 'rtsp', 'sap/r3', 'sip', 'smb', 'smtp',
                'smtp-enum', 'snmp', 'socks5', 'ssh', 'sshkey', 'subversion', 'teamspeak', 'telnet',
                'vmware-auth', 'vnc', 'xmpp', 'adam6500', 'cisco', 'ftps', 'http-proxy-urlenum', 'imaps',
                'ldap2s', 'ldap2', 'ldap3', 'mssql', 'pcanywhere', 'pop3s', 'redis', 'rpcap', 's7-300',
                'smtps', 'telnets', 'vmauthd', 'xmpp']
    service = service.lower()
    passwd_path = os.path.join(settings.BASE_DIR, settings.PASSWD_INFO_PATH)
    for ser in services:
        if ser not in service:
            if service in NAME_MAP:
                ser = NAME_MAP[service]
            else:
                continue

        try:
            logger.info('start {} passwd scan: - {}'.format(ser, target_info))
            result = start_scan(ip, port, ser, passwd_path)

        except Exception as e:
            logger.error('code 0226001 - {} - {} - {}'.format(e, e.__traceback__.tb_lineno,
                                                              e.__traceback__.tb_frame.f_globals["__file__"]))
        finally:
            pass

    return result


if __name__ == '__main__':
    target = {'ip': '185.1.33.2', 'port': '22', 'service': 'ssh',
              'application': 'jenkins', 'url': 'http://192.168.31.8:6024/'}
    print(main(target))
