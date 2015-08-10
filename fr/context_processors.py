#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.conf import settings

def get_client_ip(request):
	return {'clientIP': request.META['REMOTE_ADDR']}