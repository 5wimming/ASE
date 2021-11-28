# -*- encoding: utf-8 -*-
"""
@File    : ip_survival.py
@Time    : 2021/11/18 下午11:33
@Author  : 5wimming
"""
from .masscan_task import IpMasscan


def masscan_module(targets):
    """ip存活判断

    ip存活判断

    Args:
        targets: ip数组.

    Returns:
        无
    """
    my_scan = IpMasscan()
    result = []
    for ip in targets:
        flag = my_scan.ip_scan(ip)
        if flag == 1:
            result.append(ip)
    return result




