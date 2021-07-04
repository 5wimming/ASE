#! /usr/bin/env pyhton3
# -*- coding:utf-8 -*-
# @Date    : 2021/07/01
# @Author  : 5wimming
import zipfile
import json
import os
import csv
import requests
from ASE import settings
from StrategyModel.models import NvdCve
import logging

# cve_results = []
logger = logging.getLogger("mdjango")


def get_file_info(filepath, sql_dict):
    if not filepath.endswith('/'):
        filepath += '/'
    result = []

    for filename in os.listdir(filepath):
        if filename.endswith('.zip'):
            try:
                zip_file = zipfile.ZipFile(filepath + filename)
                for names in zip_file.namelist():
                    zip_file.extract(names, filepath)
                zip_file.close()
            except Exception as e:
                logger.error('code 0701002 - {}'.format(e))

    for filename in os.listdir(filepath):
        if filename.endswith('.json'):
            try:
                with open(filepath + filename, 'r', encoding='utf-8') as fr:
                    cve_json = json.load(fr)

                if cve_json:
                    get_cve_info(cve_json, sql_dict)
            except Exception as e:
                logger.error('code 0701003 - {}'.format(e))
    logger.info('find {} cve json'.format(len(result)))
    return result


def get_child(node, cve_data_meta, description_value, base_score, published_date, last_modified_date, sql_dict, cve_results):
    cpe_match = node.get('cpe_match', [])
    for cpe_dict in cpe_match:
        cpe23uri = cpe_dict.get('cpe23Uri', '')
        if not cpe23uri:
            continue
        cpe_info = cpe23uri.split(':')
        vendor = cpe_info[3]
        application = cpe_info[4]
        mid_version = cpe_info[5]
        version_start_including = cpe_dict.get('versionStartIncluding', '')
        version_end_including = cpe_dict.get('versionEndIncluding', '')

        dup_str = cve_data_meta + version_start_including + version_end_including + mid_version
        if dup_str in sql_dict:
            continue
        sql_dict[dup_str] = 1

        temp = [vendor, application, cve_data_meta, cpe23uri, str(version_start_including), str(version_end_including),
                str(mid_version), str(base_score), description_value, published_date, last_modified_date]
        cve_results.append(temp)

    children = node.get('children', [])
    for child in children:
        try:
            get_child(child, cve_data_meta, description_value, base_score, published_date, last_modified_date, sql_dict, cve_results)
        except Exception as e:
            logger.error('code 0704018 - {}'.format(e))


def get_cve_info(cve_data, sql_dict):
    logger.info('get cve info')
    cve_results = []
    for cve_item in cve_data['CVE_Items']:
        try:
            cve_info = cve_item['cve']
            cve_data_meta = cve_info['CVE_data_meta'].get('ID')
            description_value = cve_info.get('description', {}).get('description_data', [{}])[0].get('value', '')
            impact = cve_item.get('impact', {})
            cvss = impact.get('baseMetricV3', impact.get('baseMetricV2', {}))
            base_score = cvss.get('cvssV3', cvss.get('cvssV2', {})).get('baseScore', -1)
            published_date = cve_item.get('publishedDate', '')
            last_modified_date = cve_item.get('lastModifiedDate', '')
            nodes = cve_item['configurations']['nodes']

            if int(base_score) < settings.CVE_BASE_SCORE:
                continue

            for node in nodes:
                get_child(node, cve_data_meta, description_value, base_score, published_date, last_modified_date,
                          sql_dict, cve_results)

        except Exception as e:
            logger.error('[error] : {} - {}'.format(e, cve_item))
    if cve_results:
        logger.info('insert cve into mysql')
        for cve_result in cve_results:
            try:
                save_result = NvdCve(vendor=cve_result[0], application=cve_result[1], cve_data_meta=cve_result[2],
                                     cpe23uri=cve_result[3], version_start_including=cve_result[4],
                                     version_end_including=cve_result[5], mid_version=cve_result[6],
                                     base_score=cve_result[7], description_value=cve_result[8],
                                     published_date=cve_result[9], last_modified_date=cve_result[10])
                save_result.save()
            except Exception as e:
                logger.error('code 0702008 - {}'.format(e))

        logger.info('get {} cpe'.format(len(cve_results)))


def output_data():
    data_title = ['vendor', 'application', 'cve_data_meta', 'cpe23uri', 'version_start_including',
                  'version_end_including', 'mid_version', 'base_score', 'description_value', 'published_date',
                  'last_modified_date']
    with open('./result.csv', 'w', encoding='utf-8', newline='') as fw:
        csv_w = csv.writer(fw)
        csv_w.writerow(data_title)
        # csv_w.writerow(cve_results)


def get_new_nvd(url, file_path):
    request_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Ase/20160606 Firefox/60.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    try:
        r = requests.get(url, headers=request_headers, verify=False, timeout=1000)
        with open(file_path + url.split('/')[-1], "wb") as code:
            code.write(r.content)
        logger.info('download nvd success - {}'.format(url))
    except Exception as e:
        logger.error('code 0701001 - download nvd failed by {} - {}'.format(url, e))


def main(url, sql_dict):
    file_path = os.path.join(settings.BASE_DIR, settings.NVD_JSON_PATH)
    get_new_nvd(url, file_path)

    try:
        get_file_info(file_path, sql_dict)
    except Exception as e:
        logger.error('code 0704001 - {}'.format(e))


if __name__ == '__main__':
    main('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip')
