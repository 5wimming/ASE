# -*- encoding: utf-8 -*-
"""
@File    : web_crawler.py
@Time    : 2022/2/26 上午2:06
@Author  : 5wimming
"""

import urllib.parse
import re
import logging
import requests
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer, WebPage

logger = logging.getLogger("mdjango")


def get_url_info(url):

    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Ase/20160606 Firefox/60.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Cookie': 'rememberMe=ase',
        'X-Originating-IP': '127.0.0.1',
        'X-Client-IP': '127.0.0.1',
        'X-Forwarded-For': '127.0.0.1'
    }
    r = requests.get(url, headers=request_headers, timeout=15, verify=False)
    text_len = len(r.text)

    result = {'url': url, 'application': '', 'status': str(r.status_code), 'headers': str(r.headers).replace('\t', ' '),
              'body_size': str(text_len), 'body_content': r.text[0:2000]}

    try:
        redirect_list = r.history
        if redirect_list:
            redirect_url = redirect_list[-1].headers['Location']
            if not redirect_url.startswith('http'):
                redirect_url = url + '/' + redirect_url
        else:
            redirect_url = r.url
        result['redirect_url'] = redirect_url
        r.encoding = 'utf-8'
        soup = BeautifulSoup(r.text, 'html.parser')
        origin_title = soup.title if soup.title else "none"
        result['title'] = str(urllib.parse.unquote(origin_title)).replace("\n", " ").replace("\r", " ")\
            .replace("\t", " ").replace( "<title>", " ").replace("</title>", " ").strip()
    except Exception as e:
        logger.error('code 0226005 - {}'.format(e))

    return result


def my_wappalyzer(url):
    result = ''
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, timeout=20)
        wappalyzer_result = wappalyzer.analyze_with_versions_and_categories(webpage)

        if wappalyzer_result:
            for x in wappalyzer_result:
                versions = list(wappalyzer_result[x]['versions'])
                result += '{}({}); '.format(x, ','.join(versions))
    except Exception as e:
        pass

    return result


def main(target):
    url = target.strip()
    result = {}
    repeat_flag = False
    if not url.startswith('http'):
        url = 'http://{}'.format(url)

    try:
        result = get_url_info(url)
        if 'The plain HTTP request was sent to HTTPS port' in result['body_content'] and url.startswith('http:'):
            url = url.replace('http:', 'https:')
            result = get_url_info(url)
    except Exception as e:
        logger.error('code 0226006 - {}'.format(e))
        repeat_flag = True

    if repeat_flag:
        try:
            if url.startswith('https://'):
                url = url.replace('https://', 'http://')
            else:
                url = url.replace('http://', 'https://')

            result = get_url_info(url)
        except Exception as e:
            pass

    if result and '50' not in result.get('status', '500'):
        result['application'] = my_wappalyzer(url)

    return result


if __name__ == '__main__':
    print(main('http://139.198.21.26/phpmyadmin/'))