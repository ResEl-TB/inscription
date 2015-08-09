#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import re
from subprocess import Popen, PIPE

from django.shortcuts import render
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.http import HttpResponseRedirect

def get_mac_from_ip(request, ip, local_net):
    """ Récupère l'adresse MAC associee a l'IP fournie
    
    >>> get_mac_from_ip('172.22.201.1', '22') # '22' pour Brest, '23' pour Rennes

    """
    try:
        if re.search('172.'+ local_net + '.(20{1,3}|21{1,3}|220|221|222|223|224|225)', ip) is None:
            messages.error(request, "Votre IP ne fait pas partie du subnet ResEl Utilisateurs.")
	    return None

        mac = Popen(["ip neigh show | grep '{}'".format(ip)], stdout=PIPE, shell=True).communicate()[0].split(' ')[4].lower()

        if not mac:
            messages.error(request, "Aucun resultat avec l'hote {}".format(ip))
            return None

        return mac

    except NameError:
        messages.error(request, "Aucune adresse IP fournie.")
        return None
