#!/usr/bin/python3

import logging
from datetime import datetime, timedelta, date
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from time import sleep
from requests import post

email = ''
global_key = ''
zoneid = ''
ruleid = ''

mode = 'block'  # block | challenge | managed_challenge | js_challenge | whitelist
access_level = 'zone'  # zone | user  封禁涉及范围 *zone为单个域名下的规则 user为账户下的所有域名下的规则

frequency = 60  # 单位: 秒 每次请求所获取的时间范围 *推荐frequency与request_rate一致
request_rate = 5 # 单位: 秒 每次请求的时间间隔 *推荐frequency与request_rate一致
delay = 15 # 单位: 秒 请求时间延迟 *Cloudflare数据更新并非实时
timeout = 5 # 单位: 秒 超时时间
rate_limit = 20  # 单位: 次 IP在单位时间(frequency)内的访问次数限制
threads_num = 3  # 单位: 线程 线程池中的线程数量

log_level = logging.ERROR # DEBUG | INFO | WARNING | ERROR | CRITICAL  日志等级 *后台运行推荐设置为ERROR

logging.basicConfig(
    level=log_level, format='[%(levelname)s] %(asctime)s - %(message)s')

graphql_url = 'https://api.cloudflare.com/client/v4/graphql/'

if access_level == 'zone':
    access_url = 'https://api.cloudflare.com/client/v4/zones/' + \
        zoneid + '/firewall/access_rules/rules'
elif access_level == 'user':
    access_url = 'https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules'


headers = {
    'X-Auth-Email': email,
    'X-Auth-Key': global_key,
    'content-type': 'application/json'
}


def tester():
    logging.info('Cloudflare API 连通性测试 - 开始')
    try:
        current_iso_time = datetime.replace(
            datetime.utcnow() - timedelta(seconds=5), microsecond=0).isoformat()+'Z'
        last_iso_time = datetime.replace(
            datetime.utcnow() - timedelta(seconds=frequency), microsecond=0).isoformat()+'Z'
    except Exception as e:
        logging.error('获取时间参数: 失败')
        logging.debug(e)
        return False
    data = {"query":
            "query   ($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject){\
                    viewer{\
                        zones(filter: {zoneTag: $zoneTag}){\
                            firewallEventsAdaptive(\
                                filter: $filter\
                                limit: 1\
                                orderBy: [datetime_DESC]\
                            )\
                            {\
                            clientIP\
                            }\
                        }\
                    }\
                }",
            "variables": {
                "zoneTag": zoneid,
                "filter": {
                    "datetime_geq": last_iso_time,
                    # "datetime_leq": current_iso_time,
                    "action": "allow",
                    "ruleId": ruleid,
                }
            }
            }
    try:
        r = post(url=graphql_url, headers=headers, json=data,
                 timeout=timeout, allow_redirects=False)
    except Exception as e:
        logging.error('发送请求到 GraphQL API: 失败')
        logging.info('Cloudflare API 连通性测试 - 失败')
        logging.debug(e)
        return False
    if r.json()['errors'] is None:
        logging.info('获取 GraphQL API数据: 成功')
        logging.info('Cloudflare API 连通性测试 - 结束')
        return True
    else:
        logging.error('获取 GraphQL API数据: 失败')
        logging.info('Cloudflare API 连通性测试 - 失败')
        logging.debug(r.text)
        return False


def get_graphql_data():
    logging.info('获取 GraphQL API数据 - 开始')
    current_iso_time = datetime.replace(
        datetime.utcnow() - timedelta(seconds=delay), microsecond=0).isoformat()+'Z'
    last_iso_time = datetime.replace(
        datetime.utcnow() - timedelta(seconds=frequency+delay), microsecond=0).isoformat()+'Z'
    data = {"query":
            "query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject){\
                    viewer{\
                        zones(filter: {zoneTag: $zoneTag}){\
                            firewallEventsAdaptive(\
                                filter: $filter\
                                limit: 10000\
                                orderBy: [datetime_DESC]\
                            )\
                            {\
                            clientIP\
                            }\
                        }\
                    }\
                }",
            "variables": {
                "zoneTag": zoneid,
                "filter": {
                    "datetime_geq": str(last_iso_time),
                    "datetime_leq": str(current_iso_time),
                    "action": "allow",
                    "ruleId": ruleid,
                }
            }
            }
    try:
        r = post(url=graphql_url, headers=headers, json=data, timeout=timeout)
        print(r.text)
    except Exception as e:
        logging.error('发送请求到 GraphQL API: 失败')
        logging.debug(e)
        return False
    logging.info('获取 GraphQL API数据 - 结束')
    return handle_graphql_data(r)


def handle_graphql_data(r):
    logging.info('处理 GraphQL API数据 - 开始')
    temp_list = []
    temp_list_set = []
    ip_blacklist = []
    try:
        for i in r.json()['data']['viewer']['zones'][0]['firewallEventsAdaptive']:
            temp_list.append(i['clientIP'])
    except Exception as e:
        logging.error(e)
    temp_list_set = set(temp_list)
    for i in temp_list_set:
        if temp_list.count(i) >= rate_limit:
            ip_blacklist.append(i)
    logging.info('处理 GraphQL API数据 - 结束')
    return ip_blacklist


def handle_ip_blacklist(ip_blacklist, threadpool):
    logging.info('提交处理该批次IP黑名单 - 开始')
    if ip_blacklist == [] or ip_blacklist == False:
        logging.debug("列表为空或获取失败")
        pass
    else:
        for ip in ip_blacklist:
            logging.debug(ip)
            if len(ip) > 15:
                data = {
                    "mode": mode,
                    "configuration": {
                        "target": "ip6",
                        "value": ip
                    },
                    "notes": "Banned by Script_" + str(date.today())
                }
            else:
                data = {
                    "mode": mode,
                    "configuration": {
                        "target": "ip",
                        "value": ip
                    },
                    "notes": "Banned by Script_" + str(date.today())
                }
            threadpool.submit(send_ips, data)
    logging.info('提交处理该批次IP黑名单 - 结束')


def send_ips(data):
    logging.debug('sending ip')
    logging.debug(data)
    try:
        r = post(url=access_url, headers=headers, json=data,
                 timeout=timeout, allow_redirects=False)
    except Exception as e:
        logging.error('发送请求到 GraphQL API: 失败')
        logging.debug(e)
    if r.json()['success'] == "true":
        logging.info('已封禁')
    elif r.json()['errors'][0]['message'] == 'firewallaccessrules.api.duplicate_of_existing':
        logging.warn('重复封禁')
    else:
        logging.warn('封禁失败')


def create_threadpool():
    t = ThreadPoolExecutor(max_workers=threads_num)
    return t


def main():
    if tester():
        pass
    else:
        exit(1)
    threadpool = create_threadpool()
    while 1:
        logging.info('循环执行 - 开始')
        status = handle_ip_blacklist(get_graphql_data(), threadpool)
        logging.info('循环执行 - 结束')
        logging.info('等待 %s 秒后再次执行' % request_rate)
        sleep(request_rate)

if __name__ == '__main__':
    main()
