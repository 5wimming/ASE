"""
Django settings for ASE project.

Generated by 'django-admin startproject' using Django 3.2.3.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""
# -*- coding: UTF-8 -*-

from pathlib import Path
import os
import logging


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-40#$#^#=(zhj6h=ugw4u#k^a0gie(k3q(t5z=6)+&lv#uyy=g1'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'simpleui',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'import_export',
    'django.contrib.staticfiles',
    'AseModel',
    'TaskModel',
    'StrategyModel',
    # 'multi_captcha_admin',  # 1 验证码需要顺序
    'django.contrib.admin',  # 2
    # 'captcha',  # 3
]

# 验证码配置
MULTI_CAPTCHA_ADMIN = {
    'engine': 'simple-captcha',
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ASE.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'ASE/templates')],  # 模版位置
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
IMPORT_EXPORT_USE_TRANSACTIONS = True
WSGI_APPLICATION = 'ASE.wsgi.application'
MEDIA_URL = '/files/'

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default':
        {
            'ENGINE': 'django.db.backends.mysql',  # 数据库引擎
            'NAME': 'ase_data',  # 数据库名称
            'HOST': '127.0.0.1',  # 数据库地址，本机 ip 地址 127.0.0.1
            'PORT': 3306,  # 端口
            'USER': 'root',  # 数据库用户名
            'PASSWORD': '123456',  # 数据库密码
        }
}

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'zh-hans'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = True

SIMPLEUI_HOME_TITLE = 'Asset Scan Engine'
SIMPLEUI_LOGO = '../static/images/logo5.png'


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "statics"),
]

IPS_FILE_PATH = 'ips_txt/'

TEMP_DIR = os.path.join(BASE_DIR, "temp")
if not os.path.exists(TEMP_DIR):
    os.mkdir(TEMP_DIR)

LOGGING_DIR = os.path.join(BASE_DIR, "logs")
if not os.path.exists(LOGGING_DIR):
    os.mkdir(LOGGING_DIR)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '[%(levelname)s][%(asctime)s][%(filename)s][%(funcName)s][%(lineno)d] > %(message)s'
        },
        'simple': {
            'format': '[%(levelname)s]> %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
    },
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'simple'

        },
        'file_handler': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': '%s/django.log' % LOGGING_DIR,
            'formatter': 'standard',
            'backupCount': 30,
            'encoding': 'utf-8'
        },  # 用于文件输出
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'standard'
        },
    },
    'loggers': {
        'mdjango': {
            # 一个记录器中可以使用多个处理器
            'handlers': ['console', 'file_handler'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': False,
        },
    }
}

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
SIMPLEUI_INDEX = '/ase'
STRATEGY_TOOLS_PATH = 'StrategyTools/'
SIMPLEUI_HOME_INFO = False
SIMPLEUI_ANALYSIS = False