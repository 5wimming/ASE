# -*- encoding: utf-8 -*-
"""
@File    : masscan_task.py
@Time    : 2021/11/18 下午11:33
@Author  : 5wimming
"""

import random
import time
import masscan
import logging

logger = logging.getLogger("mdjango")


class IpMasscan:

    def __init__(self, masscan_args='--wait 5 --rate 5000'):
        self.masscan_args = masscan_args
        self.masscan = masscan.PortScanner()

    def port_scan(self, targets, port):
        """端口存活扫描

        端口存活扫描

        Args:
            targets: ip数组.
            port: 端口.

        Returns:
            无
        """
        if len(targets) < 1:
            return targets

        targets1 = []
        targets2 = []
        for i, value in enumerate(targets):
            targets1.append(value)
            if (i + 1) % 1000 == 0:
                targets2.append(targets1)
                targets1 = []

        if targets1:
            targets2.append(targets1)

        results = set()
        for targets in targets2:
            for i in range(2):
                scan_result = {}
                random.shuffle(targets)
                target_str = ','.join(targets)
                try:
                    scan_result = self.masscan.scan('"{}"'.format(target_str), ports=port,
                                                    arguments=self.masscan_args)
                    break
                except Exception as e:
                    logger.error('{} --- {} --- {}'.format(e,
                                                           e.__traceback__.tb_lineno,
                                                           e.__traceback__.tb_frame.f_globals["__file__"]))
                finally:
                    pass

                scan_ips = scan_result.get('scan', {})
                for ip, value in scan_ips.items():
                    port_state = value.get('tcp', {}).get(int(port), {}).get('state', '')
                    if 'open' in port_state:
                        results.add(ip)
                time.sleep(0.1)

        return list(results)

    def ip_scan(self, targets, ports_str):
        """ip存活扫描

        ip存活扫描

        Args:
            targets: ip.
            ports_str: 端口数据

        Returns:
            无
        """
        # 40个
        ports = '21,22,23,25,53,80,110,111,123,135,139,143,161,443,445,993,995,1080,1433,1434,1723,3128,3389,4750,' \
                '5900,8080,8081,9101,9080,18080,28080,37111,37112,37113,37114,37115,37116,37117,37118,37119'
        if ports_str:
            ports = ports_str
        result_ip = set()
        result_port = set()
        for i in range(2):
            try:
                scan_result = self.masscan.scan('"{}"'.format(','.join(targets)),
                                                ports=ports,
                                                arguments=self.masscan_args)
                scan_ips = scan_result.get('scan', {})
                for ip, value in scan_ips.items():
                    logger.info('subtask masscan result: [{}] --- [{}]'.format(ip, value))
                    value_dict = value.get('tcp', {})
                    if len(value_dict.items()) > 1024:
                        continue

                    result_ip.add(ip)
                    for port_temp in value_dict.keys():
                        result_port.add(port_temp)

                    time.sleep(0.2)
            except Exception as e:
                logger.error('{} --- {} --- {}'.format(e,
                                                       e.__traceback__.tb_lineno,
                                                       e.__traceback__.tb_frame.f_globals["__file__"]))
            finally:
                pass

        return list(result_ip), list(result_port)


if __name__ == '__main__':
    my_scan = IpMasscan('--wait 15 --rate 10000')
    print(my_scan.ip_scan(
        '129.204.131.185,129.204.131.237,129.204.131.245,129.204.131.99,129.204.131.117,129.204.131.158,129.204.131.166,129.204.131.102,129.204.131.28,129.204.131.233,129.204.131.80,129.204.131.37,129.204.131.231,129.204.131.210,129.204.131.69,129.204.131.44,129.204.131.167,129.204.131.54,129.204.131.160,129.204.131.144,129.204.131.151,129.204.131.182,129.204.131.107,129.204.131.82,129.204.131.170,129.204.131.206,129.204.131.201,129.204.131.73,129.204.131.141,129.204.131.154,129.204.131.11'.split(
            ','),
        '1-1024,1080,1433,1434,1723,3128,3389,4750,900,8080,8081,9101,9080'))
