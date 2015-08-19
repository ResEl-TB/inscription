#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from constants import ldap_admin_dn, ldap_admin_passwd

"""
Django settings for inscription project.

Generated by 'django-admin startproject' using Django 1.8.3.

For more information on this file, see
https://docs.djangoproject.com/en/1.8/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.8/ref/settings/
"""

import ldap
from django_auth_ldap.config import LDAPSearch, PosixGroupType

# Config pour l'envoi de mails
SERVER_EMAIL = 'django-inscription@resel.fr'
EMAIL_USE_TLS = True
EMAIL_HOST = 'pegase.adm.maisel.enst-bretagne.fr'

ADMINS = [
    ('Inscription.resel.fr', 'inscription@resel.fr'),
]

# Config pour Django-auth-ldap

AUTH_LDAP_SERVER_URI = "ldap://ldap.maisel.enst-bretagne.fr:389"

AUTH_LDAP_BIND_DN = ldap_admin_dn
AUTH_LDAP_BIND_PASSWORD = ldap_admin_passwd
AUTH_LDAP_USER_SEARCH = LDAPSearch("ou=people,dc=maisel,dc=enst-bretagne,dc=fr",
    ldap.SCOPE_SUBTREE, "(uid=%(user)s)")

AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.ModelBackend',
)

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'vz1ntr)*e*t88#v4cp89()a4a)euiad37ipf3hkqueo3vlmw2j'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Config pour le client IRC Gnotty
GNOTTY_IRC_HOST = 'irc.resel.fr'
GNOTTY_IRC_PORT = 6767
GNOTTY_IRC_CHANNEL = '#resel'

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'fr',
    'en',
    'gnotty',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'inscription.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates'),'/var/www/inscription/static/inscription/'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'fr.context_processors.get_client_ip'
            ],
        },
    },
]

WSGI_APPLICATION = 'inscription.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'FR-fr'

TIME_ZONE = 'Europe/Paris'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/

STATIC_URL = '/static/'

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "static"),
)

# Expiration de session pour les users connectés
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
