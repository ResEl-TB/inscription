#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.shortcuts import render

# Create your views here.
def Choix(request):
	""" Vue pour choisir une auth LDAP ou CAS école """
	return render(request, 'accueil/auth_choice.html')