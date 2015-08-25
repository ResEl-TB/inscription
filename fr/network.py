#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import re
from subprocess import Popen, PIPE

from django.shortcuts import render
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.http import HttpResponseRedirect

from ldap_func import search

def get_mac_from_ip(request, ip, local_net):
    """ Récupère l'adresse MAC associee a l'IP fournie
    
    >>> get_mac_from_ip('172.22.201.1', '22') # '22' pour Brest, '23' pour Rennes

    """
    try:
        if re.search('172.'+ local_net + '.(20{1,3}|21{1,3}|220|221|222|223|224|225)', ip) is None:
            messages.error(request, "Votre IP ne fait pas partie du subnet ResEl Utilisateurs.")
            return None

        #mac = Popen(["sudo arping -c 1 -I eth2:1 {}".format(ip)], stdout=PIPE, shell=True).communicate()[0].split('from')[1].split(' ')[1].lower()
	mac = Popen(["ip neigh show | grep '{}\\s' | awk '{{print $5}}'".format(ip)], stdout=PIPE, shell=True).communicate()[0].lower().split('\n')[0]

        if not mac:
            messages.error(request, "Aucun resultat avec l'hote {}".format(ip))
            return None

        return mac
    except:
        messages.error(request, "Erreur dans la récupération de votre adresse MAC. Veuillez réinitialiser votre connexion et réessayer. Si le problème persiste, contactez un administrateur ResEl.")
        return None

def get_free_ip(low, high):
    """
    Récupère une IP libre pour une nouvelle machine à partir du LDAP
    """
    rang = low - 1
    again = True

    while ((rang < high) and again):
        rang += 1
        item = 2

        while ((item < 254) and again):
            item +=1
            if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(ipHostNumber={}.{})".format(rang, item)) is None:
                again = False

    return "{}.{}".format(rang, item)

def update_dhcp_dns_firewall():
    Popen(['ssh -t reloader@dynasty.adm.maisel.enst-bretagne.fr 2>&1'], stdout=PIPE, shell=True)
    Popen(['ssh -t updatefirewall@loli -p 2222 2>&1'], stdout=PIPE, shell=True)








