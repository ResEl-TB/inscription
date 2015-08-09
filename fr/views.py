#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login
from django.core.mail import mail_admins

import re

from .network import get_mac_from_ip
from .ldap_func import *
from .forms import AdhesionForm
from .models import Profil

def Verification(request):
	clientIP = request.META['REMOTE_ADDR']

	if re.search('172.22.(20{1,3}|21{1,3}|220|221|222|223|224|225)', clientIP):
		return HttpResponseRedirect(reverse('fr:index'))
		
	else:
		messages.error(request, 'Votre IP ne correspond pas à une IP du type 172.22.22(4-5).Y ; Veuillez configurer votre carte réseau pour obtenir une IP via DHCP.')
		return HttpResponseRedirect(reverse('fr:erreur'))

def Erreur(request):
	return render(request, 'fr/erreur.html')

def Index(request):
	clientIP = request.META['REMOTE_ADDR']
	machineInactive = False

	if clientIP.split('.')[1] == '23': # On bascule vers inscription.rennes si l'user se connecte de Rennes
		return redirect('http://inscription.rennes.resel.fr')

	if clientIP != "172.22.42.4" and inactive(request, get_mac_from_ip(request, clientIP, '22')): # Vérification que la machine est active
		machineInactive = True

	if messages.get_messages(request):
		return HttpResponseRedirect(reverse('fr:erreur'))

	return render(request, 'fr/index.html', {'machineInactive': machineInactive})

def Login(request):
    """
    Displays the login form and handles the login action.
    """
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())

            return HttpResponseRedirect(reverse('fr:ajout'))
    else:
        form = AuthenticationForm(request)

    context = {
        'form': form,
    }

    return render(request, 'fr/login.html', context)

@login_required(login_url='/fr/login')
def Ajout(request):
	clientIP = request.META['REMOTE_ADDR']
	mac = get_mac_from_ip(request, clientIP, '22')
	uid = str(request.user.username)
	statuts = get_status(request, uid)
	
	if blacklist(request, uid):
		messages.error(request, "Vous n'avez pas payé votre cotisation, vous n'avez donc pas l'autorisation de vous inscrire.<br />Veuillez contacter un administrateur ResEl par mail à l'adresse <a href='mailto:inscription@resel.fr'>inscription@resel.fr</a> en précisant votre uid : <strong>{}</strong>".format(uid))

	if inactive(request, mac):
		return HttpResponseRedirect(reverse('fr:reactivation'))

	if 'genericPerson' not in statuts:
		messages.error(request, "LDAP : il manque l'attribut 'genericPerson' pour l'uid {}".format(uid))
		mail_admins("[Inscription Brest] {} inconnu".format(uid), "Pour votre information, la personne d'uid {}, a tenté de s'inscrire. Elle ne possède pas d'attribut 'genericPerson'.\n\nIP : {} - MAC : {}\nNavigateur : {}\n\n-- \n".format(uid, clientIP, mac, request.META['HTTP_USER_AGENT']), fail_silently=False, connection=None, html_message=None)

	if ('enstbPerson' not in statuts) and ('guestPerson' not in statuts):
		messages.error(request, "Vous n'êtes pas une personne enregistrée à Télécom Bretagne. Pour pouvoir vous inscrire veuillez contacter <a href=\"mailto:inscription@resel.fr\">inscription@resel.fr</a>.")
		mail_admins("[Inscription Brest] {} inconnu".format(uid), "Pour votre information, la personne d'uid {}, a tenté de s'inscrire. Elle n'est ni 'enstbPerson' ni 'guestPerson'.\n\nIP : {} - MAC : {}\nNavigateur : {}\n\n-- \n".format(uid, clientIP, mac, request.META['HTTP_USER_AGENT']), fail_silently=False, connection=None, html_message=None)

	inscrit_resel = False
	if 'reselPerson' in statuts:
		inscrit_resel = True
		machines = search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(uidProprio=uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr)".format(uid))[0]

	if messages.get_messages(request):
		return HttpResponseRedirect(reverse('fr:erreur'))

	return render(request, 'fr/ajout.html')

@login_required(login_url='/fr/login')
def Reactivation(request):
	return render(request, 'fr/reactivation.html')

@login_required(login_url='/fr/login')
def Devenir_membre(request):
	if request.method == 'POST':
		form = AdhesionForm(request.POST)

		if form.is_valid():
			accepted = form.cleaned_data['accepted']

			if accepted:
				uid = str(request.user.username)
				ajouter(uid)

	return render(request, 'fr/devenir_membre.html')


















