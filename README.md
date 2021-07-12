# ASE

相信很多安全人员，经常会写一些验证性POC，而这些好东西用完经常就被放在了某个角落，想再用的时候又要翻半天，一直希望有一个比较好的开源扫描平台可以存放这些东西，供自己或者大家直接使用。

ASE是我利用下班、放假时间，前后花了一个多月写出来的，也许并不复杂，主要是经常晚上加班累了，回来就不想写了，再加上一点都不会前端，因此断断续续写了一个多月。

之所以选择python，主要是方便、好学、易用、库多，比如用python编写了一个POC，直接就可以通过ASE放进扫描器，不用进行复杂的编译。
## ASE
ASE(Asset Scan Engine)是一个简单的基于BS的主机、域名扫描器，但它又可以没那么简单。

ASE是开源的，扫描的漏洞策略是可自行定制添加的；并且提供了nvd漏洞库的自动更新接口，使得在没有漏洞策略的情况下，通过版本匹配相应漏洞。

相对于nexpose、nessus等这类庞大的扫描器，我希望ASE未来只收纳几十到几百种高危可远程利用的扫描策略，诸如命令注入、反序列化、任意文件上传下载等这类可远程利用的漏洞。
### ASE主要功能
1、发现开放端口的服务，如协议、应用、版本等

2、发现http的相关服务，如title、返回头、状态等

3、与nvd库进行比较，发现版本存在漏洞的应用

4、定制扫描策略，扫描特定漏洞

5、提供3和4的更新接口，可自动化更新
### 用户群体
- 个人
- 小型企业
- 小型实验室

### 界面

首页地址：http://127.0.0.1:58088/ase

任务界面
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712005807571.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)
## ASE的使用
### 创建任务
目前只支持扫描ip和域名
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712223143597.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712223215876.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)
### 更新扫描策略
左侧，从上到下，依次是CVE策略更新，自建扫描策略
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712223330952.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)
nvd更新接口
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712223648805.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)
### 扫描结果
有三种结果，端口扫描结果、漏洞结果、web信息结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713004600508.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713004537607.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071222390556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)


## docker安装

首页地址：http://127.0.0.1:58088/ase


[docker地址](https://registry.hub.docker.com/repository/docker/new6ee/ase)

```java
version: '2.2'
services:
  ase:
    image: new6ee/ase:1.7
    ports:
      - "58088:8080"
    init: true
```
保存到docker-compose.yml
运行命令

```java
docker-compose up -d
```

## 源码安装
### 源码获取
[github](https://github.com/5wimming/ASE)

### mysql安装

#### linux

linux安装：
apt-get install mysql-server
service mysql start

本项目的mysql密码：

```
Ase5scan.
```
### redis安装

```java
sudo apt-get install redis-server
```

### 依赖库安装

```
python3 -m pip install Django==3.2.4
python3 -m pip install mysqlclient
python3 -m pip install django-simpleui==2021.6.2
python3 -m pip install IPy django-import-export
python3 -m pip install python-nmap
python3 -m pip install beautifulsoup4
python3 -m pip install requests
python3 -m pip install django-redis

python3 -m pip Django==3.2.4 mysqlclient django-simpleui IPy django-import-export python-nmap beautifulsoup4 requests
# 更新命令，没事别更新，会有不兼容的情况出现
python3 -m pip install Django django-simpleui --upgrade
```


### 工程搭建

创建数据库

```
create database ase_data default charset=utf8;
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623220358326.png)

创建表结构

```
python3 manage.py makemigrations
python3 manage.py migrate
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623220504386.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM0MTAxMzY0,size_16,color_FFFFFF,t_70)

创建超级用户


```bash
python3 manage.py createsuperuser
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623221145396.png)

```java
用户名：ase005
密码：ase005.
```

开启项目

```java
python3 manage.py runserver 0.0.0.0:8080 --insecure
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623221425166.png)

## 申明
ASE只可用于做个人资产的安全排查，切勿他用，否则后果自负
