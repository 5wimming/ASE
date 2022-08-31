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

    def port_scan(self, targets, ports):
        """端口存活扫描

        端口存活扫描

        Args:
            targets: ip数组.
            ports: 端口.

        Returns:
            无
        """
        result_ip_port = []
        try:
            scan_result = self.masscan.scan('"{}"'.format(','.join(targets)),
                                            ports=ports,
                                            arguments=self.masscan_args)
            scan_ips = scan_result.get('scan', {})
            for ip, value in scan_ips.items():
                value_dict = value.get('tcp', {})
                if len(value_dict.items()) < 1:
                    continue
                for port in value_dict.keys():
                    result_ip_port.append(f'{ip}:{port}')

            time.sleep(0.5)
        except Exception as e:
            logger.error('{} --- {} --- {}'.format(e,
                                                   e.__traceback__.tb_lineno,
                                                   e.__traceback__.tb_frame.f_globals["__file__"]))
        finally:
            pass

        return result_ip_port

    def ip_scan(self, targets):
        """ip存活扫描

        ip存活扫描

        Args:
            targets: ip list

        Returns:
            存活ip list
        """
        # 15
        ports = '21,22,23,25,53,80,161,443,445,1080,3306,3389,8080,8443,9101'
        try:
            scan_result = self.masscan.scan('"{}"'.format(','.join(targets)),
                                            ports=ports,
                                            arguments=self.masscan_args)
            scan_ips = scan_result.get('scan', {})
            result_ips = list(scan_ips.keys())

            return result_ips
        except Exception as e:
            logger.error('{} --- {} --- {}'.format(e,
                                                   e.__traceback__.tb_lineno,
                                                   e.__traceback__.tb_frame.f_globals["__file__"]))
        return []


if __name__ == '__main__':
    my_scan = IpMasscan('--wait 5 --rate 10000')
    print(my_scan.ip_scan(
        '10.10.10.10'.split(
            ',')))
