#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# @Date    : 2021/06/20
# @Author  : 5wimming

import socket

readme = {'strategy_name': 'redis_unauthorized_access', 'service_name': 'redis',
          'port': '6379', 'application': 'redis', 'proto': 'tcp', 'version': '',
          'remarks': '', 'cpe': '', 'vendor': ''}
weakly_passwords = ['redis', 'redis123', 'Redis123', 'redis@123', 'root', 'oracle', 'password', 'p@ssw0rd', 'abc123!',
                    '123456', 'admin', 'abc123', 'admin12', 'admin888', 'admin8', 'admin123', 'sysadmin', 'adminxxx',
                    'adminx', '6kadmin', 'base', 'feitium', 'admins', 'roots', 'test', 'test1', 'test123', 'test2',
                    'aaaAAA111', '888888', '88888888', '000000', '00000000', '111111', '11111111', 'aaaaaa', 'aaaaaaaa',
                    '135246', '135246789', '654321', '12345', '54321', '123456789', '1234567890', '123qwe', '123qweasd',
                    'qweasd', '123asd', 'qwezxc', 'qazxsw', 'qazwsx', 'qazwsxedc', '1qaz2wsx', 'zxcvbn', 'asdfgh',
                    'qwerty', 'qazxdr', 'qwaszx', '123123', '123321', 'abcdef', 'abcdefg', 'asd123', 'qweasdzxc',
                    'zxcvb', 'asdfg', 'qwert', 'welcome', 'ABC_abc1', 'Admin@1234']


def unauthorized_access_scan(target_info):
    scan_result = False
    ip = target_info['ip']
    port = target_info['port']
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("INFO\r\n".encode())
        result = s.recv(1024).decode()

        if "redis_version" in result:
            scan_result = True
    except Exception as e:
        print('unauthorized access scan:', e)
    finally:
        s.close()
    return scan_result


def weak_password_scan(target_info, password):
    ip = target_info['ip']
    port = target_info['port']
    try:
        passwd = password.strip("\n")
        socket.setdefaulttimeout(2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send(("AUTH %s\r\n" % passwd).encode())
        result = s.recv(1024).decode()

        if 'OK' in result:
            return True

    except Exception as e:
        pass
    finally:
        s.close()

    return False


def main(target_info, *args):
    try:
        if unauthorized_access_scan(target_info):
            return True
        else:
            for password in weakly_passwords:
                if weak_password_scan(target_info, password):
                    return True
    except Exception as e:
        pass

    return False


if __name__ == '__main__':
    target = {'ip': '127.0.0.1', 'port': '6379', 'service': 'redis', 'application': 'redis'}
    print(main(target))
