#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from constants import ldap_admin_dn, ldap_admin_passwd, dn_ecole

import ldap
from datetime import datetime
import time
import hashlib
import os
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode

from django_auth_ldap.config import LDAPSearch
from django.shortcuts import render
from django.core.urlresolvers import reverse
from django.contrib import messages

def inactive(mac):
    """
    Regarde si la machine est active ou non
    """
    if mac:
        machine = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )
        if machine:
            return ('Inactive' in machine[0][1]['zone'])
        else:
            return False
    else:
        return False

def search(base_dn, filters):
    """
    Cherche dans le ldap avec les paramètres fournis
    """
    l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    results = l.search_s(base_dn, ldap.SCOPE_SUBTREE, filters)
    if len(results) == 0:
    	return None
    return results

def search_ecole(uid):
    """ Cherche dans le LDAP école avec l'uid fournie """
    l = ldap.open('10.29.90.34')
    l.simple_bind()
    return l.search_s(dn_ecole, ldap.SCOPE_SUBTREE, "(uid=%s)" % uid)[0][1]

def blacklist(request, uid):
    """ 
    Vérifie si un utilisateur est blacklisté 
    """
    if uid:
        result = search('ou=people,dc=maisel,dc=enst-bretagne,dc=fr', "(uid={})".format(uid))
        if result:
            if result[0][1]['cotiz']:
                year = datetime.now().year
                month = datetime.now().month

                if month < 9:
                    year -= 1

                return ('BLACKLIST{}'.format(year) in result[0][1]['cotiz'])
            else:
                return False
        else:
            messages.error(request, "User {} is not on the LDAP.".format(uid))
            return False
    else:
        messages.error(request, "The uid provided for the 'blacklist' function is 'None'.")
        return False

def check_uid_mac(request, uid, mac):
    """
    Vérifie que la mac fournie est bien associée à l'uid fourni.
    Renvoi False en cas d'erreur, et le tuple (proprio, alias) correspondant 
    à l'uid propriétaire de la machine ainsi que l'alias de la dite machine
    """
    if uid and mac:
        result = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )
        if result:
            proprio = result[0][1]['uidproprio'][0].split('=')[1].split(',')[0]
            alias = result[0][1]['host'][0]
            return (proprio, alias)
        else:
            messages.error(request, "MAC adress {} does not appear in the LDAP.".format(mac))
            return False
    else:
        messages.error(request, "A parameter for the function 'check_uid_mac' is 'None'.")
        return False

def get_status(request, uid):
    """
    Retourne une liste des objectClass de l'uid fourni, et None en cas d'erreur
    """
    if uid:
        result = search( "ou=people,dc=maisel,dc=enst-bretagne,dc=fr" , "(uid={})".format(uid) )
        if result:
            status = result[0][1]['objectClass']
            return status
        else:
            messages.error(request, "User {} is not in the LDAP.".format(uid))
            return None
    else:
        messages.error(request, "The uid provided for the function 'get_status' is 'None'.")
        return None

def inscrire_user(uid):
    """
    Ajoute l'objectClass 'reselPerson' ainsi que la date d'inscription à la fiche ldap de l'uid
    """
    mod_attrs = [
        ( ldap.MOD_ADD, 'dateinscr', "{}Z".format(time.strftime('%Y%m%d%H%M%S')) ),
        ( ldap.MOD_ADD, 'objectClass', 'reselPerson' )
    ]

    l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    l.modify_s('uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr'.format(uid), mod_attrs)
    l.unbind()

def update_campus(machine):
    """
    Met a jour le campus d'une machine
    """
    mod_attrs = [
        ( ldap.MOD_DELETE, 'zone', 'Rennes' ),
        ( ldap.MOD_ADD, 'zone', 'Brest' )
    ]

    l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    l.modify_s(machine[0], mod_attrs)
    l.unbind()

def add_entry(dn, attrs):
    """
    Ajoute une entrée dans le LDAP
    """
    l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    l.add_s(dn, attrs)
    l.unbind()

def mod(dn, attrs):
    """
    Modifie la fiche LDAP correspondant au DN fourni, en fonction des attributs attrs
    """
    l = ldap.initialize('ldap://ldap.maisel.enst-bretagne.fr')
    l.simple_bind_s(ldap_admin_dn, ldap_admin_passwd)
    l.modify_s(dn, attrs)
    l.unbind()

def get_free_alias(uid):
    """
    Récupère un alias automatiquement pour l'ajout d'une nouvelle machine
    """
    test = 'pc{}'.format(uid)
    result = search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(Hostalias={})".format(test))

    if result is not None:
        continuer = True
        i = 2
        while continuer:
            test = 'pc{}{}'.format(uid, i)
            i += 1
            if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(hostAlias={})".format(test)) == None:
                if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(hostAlias=0{})".format(test)) == None:
                    continuer = False
    return test

def hashPassword(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)





