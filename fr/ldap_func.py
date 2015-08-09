#!/usr/local/bin/python
# -*- coding: utf-8 -*-
from constants import ldap_admin_dn, ldap_admin_passwd

import ldap
from datetime import datetime
import time

from django_auth_ldap.config import LDAPSearch
from django.shortcuts import render
from django.core.urlresolvers import reverse
from django.contrib import messages

def inactive(request, mac):
    """
    Search in the LDAP if user's machine is active or not
    """
    try:
	if mac is not None:
		result = search('ou=machines,dc=resel,dc=enst-bretagne,dc=fr', "(macAddress={})".format(mac))
		if result:
	    		return ('Inactive' in result[0][1]['zone'])
		else:
			messages.error(request, "La MAC {} n'est pas connue dans notre annuaire LDAP.".format(mac))
	    		return False
	else:
		messages.error(request, "get_mac_from_ip a fourni le paramètre 'None'.")
		return False
    except NameError:
	messages.error(request, "Aucune MAC fournie en paramètre pour la fonction 'inactive'.")
	return False

def search(base_dn, filters):
    """
    Performs a search in the LDAP with the given parameters
    """
    l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    results = l.search_s(base_dn, ldap.SCOPE_SUBTREE, filters)
    return results

def blacklist(request, uid):
    	""" Check if a user is blacklisted """
	if uid:
		result = search('ou=people,dc=maisel,dc=enst-bretagne,dc=fr', "(uid={})".format(uid))
		if result:
			year = datetime.now().year
			month = datetime.now().month

			if month < 9:
				year -= 1

			return ('BLACKLIST{}'.format(year) in result[0][1]['cotiz'])
		else:
			messages.error(request, "L'user {} n'est pas présent dans l'annuaire LDAP".format(uid))
			return False
	else:
		messages.error(request, "L'uid fourni a la fonction 'blacklist' vaut 'None'.")
		return False

def check_uid_mac(request, uid, mac):
	if uid and mac:
		result = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )
		if result:
			proprio = result[0][1]['uidproprio'][0].split('=')[1]
			alias = result[0][1]['host'][0]
			return (proprio, alias)
		else:
			messages.error(request, "La MAC {} n'est pas connue dans notre annuaire LDAP.".format(mac))
			return False	
	else:
		messages.error(request, "Un des paramètres fourni a la fonction 'check_uid_mac' vaut 'None'.")
		return False

def get_status(request, uid):
	if uid:
		result = search( "ou=people,dc=maisel,dc=enst-bretagne,dc=fr" , "(uid={})".format(uid) )
		if result:
			status = result[0][1]['objectClass']
			return status
		else:
			messages.error(request, "L'user {} n'existe pas dans le LDAP.".format(uid))
			return None
	else:
		messages.error(request, "L'uid fourni dans la fonction 'get_status' vaut 'None'.")
		return None

def ajouter(uid):
	mod_attrs = [
		( ldap.MOD_ADD, 'dateinscr', "{}Z".format(time.strftime('%Y%m%d%H%M%S')) ),
		( ldap.MOD_ADD, 'objectClass', 'reselPerson' )
	]
	
	l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    l.modify_s('uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr'.format(uid), mod_attrs)
    l.unbind()

def update_campus(machine):
	mod_attrs = [
		( ldap.MOD_DELETE, 'zone', 'Brest' ),
		( ldap.MOD_ADD, 'zone', 'Rennes' )
	]
	
	l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    l.modify_s(machine[0], mod_attrs)
    l.unbind()





