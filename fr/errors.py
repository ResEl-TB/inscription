#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.shortcuts import render_to_response
from django.template import RequestContext

# HTTP Erreur 404
def page_not_found(request):
	response = render_to_response(
        'fr/errors/404.html',
        context_instance=RequestContext(request)
    )
    
    response.status_code = 400
    
    return response