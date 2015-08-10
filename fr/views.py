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
import time

from .network import *
from .ldap_func import *
from .forms import AdhesionForm, AliasForm
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

            return HttpResponseRedirect(reverse('fr:index_secure'))
    else:
        form = AuthenticationForm(request)

    context = {
        'form': form,
    }

    return render(request, 'fr/login.html', context)

@login_required(login_url='/fr/login')
def Index_secure(request):
	clientIP = request.META['REMOTE_ADDR']
	mac = get_mac_from_ip(request, clientIP, '22')
	uid = str(request.user.username)
	statuts = get_status(request, uid)
	machine_connue = False
	
	if messages.get_messages(request):
		return HttpResponseRedirect(reverse('fr:erreur'))

	request.META['uid_client'] = uid
	request.META['mac_client'] = mac

	if blacklist(request, uid):
		messages.error(request, "Vous n'avez pas payé votre cotisation, vous n'avez donc pas l'autorisation de vous inscrire.<br />Veuillez contacter un administrateur ResEl par mail à l'adresse <a href='mailto:inscription@resel.fr'>inscription@resel.fr</a> en précisant votre uid : <strong>{}</strong>".format(uid))
		return HttpResponseRedirect(reverse('fr:erreur'))

	if messages.get_messages(request):
		return HttpResponseRedirect(reverse('fr:erreur'))

	if 'genericPerson' not in statuts:
		messages.error(request, "LDAP : il manque l'attribut 'genericPerson' pour l'uid {}".format(uid))
		mail_admins("[Inscription Brest] {} inconnu".format(uid), "Pour votre information, la personne d'uid {}, a tenté de s'inscrire. Elle ne possède pas d'attribut 'genericPerson'.\n\nIP : {} - MAC : {}\nNavigateur : {}\n\n-- \n".format(uid, clientIP, mac, request.META['HTTP_USER_AGENT']), fail_silently=False, connection=None, html_message=None)
		return HttpResponseRedirect(reverse('fr:erreur'))

	if ('enstbPerson' not in statuts) and ('guestPerson' not in statuts):
		messages.error(request, "Vous n'êtes pas une personne enregistrée à Télécom Bretagne. Pour pouvoir vous inscrire veuillez contacter <a href=\"mailto:inscription@resel.fr\">inscription@resel.fr</a>.")
		mail_admins("[Inscription Brest] {} inconnu".format(uid), "Pour votre information, la personne d'uid {}, a tenté de s'inscrire. Elle n'est ni 'enstbPerson' ni 'guestPerson'.\n\nIP : {} - MAC : {}\nNavigateur : {}\n\n-- \n".format(uid, clientIP, mac, request.META['HTTP_USER_AGENT']), fail_silently=False, connection=None, html_message=None)
		return HttpResponseRedirect(reverse('fr:erreur'))

	context = {}
	context['inscrit_resel'] = False
	if 'reselPerson' in statuts:
		request.META['nb_machines'] = 0
		context['inscrit_resel'] = True
		machines = search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(uidProprio=uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr)".format(uid))

		if machines:
			context['machines'] = machines
			request.META['nb_machines'] = len(machines)

			if type(mac) is int:
				messages.error(request, "Problème lors de la récupération de l'adresse MAC.")
				return HttpResponseRedirect(reverse('fr:erreur'))

			if mac is '00:00:00:00:00:00':
				messages.error(request, "Votre adresse MAC vaut '00:00:00:00:00:00', veuillez contacter un administrateur ResEl.")
				return HttpResponseRedirect(reverse('fr:erreur'))

			if re.search(r'^00:00:6c', mac):
				messages.error(request, "Votre ordinateur utilise une adresse MAC commençant par 00:00:6c, ce qui est un bug avec certains systèmes d'exploitation, constaté notamment sous Ubuntu. Contactez le ResEl pour plus d'informations.")
				mail_admins("[Inscription Brest] Mac {} par {}".format(uid), "Pour votre information, la personne d'uid {} a une adresse MAC bugguée.\n\nIP : {} - MAC : {}\nNavigateur : {}\n\n-- \n".format(mac, uid, uid, clientIP, mac, request.META['HTTP_USER_AGENT']), fail_silently=False, connection=None, html_message=None)
				return HttpResponseRedirect(reverse('fr:erreur'))

			machine_user = search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAdress={})".format(mac))[0]

			if machine_user:
				proprio = machine_user[1]['uidProprio'].split('=')[1].split(',')[0]

				if uid != proprio:
					messages.error(request, "La machine que vous utilisez appartient à l'uid {}. Veuillez prendre contact avec un administrateur ResEl afin de clarifier la situation.".format(proprio))
					mail_admins("[Inscription Brest] Mauvais proprio pour la MAC {}".format(mac), "Pour votre information, l'utilisateur {} a tenté d'enregistrer une machine appartenant à l'uid {}.\n\nIP : {} - MAC : {}\nNavigateur : {}\n\n-- \n".format(uid, proprio, clientIP, mac, request.META['HTTP_USER_AGENT']), fail_silently=False, connection=None, html_message=None)
					return HttpResponseRedirect(reverse('fr:erreur'))

				else:
					machineIP = '172.22.' + machine_user[1]['ipHostNumber'][0]

					if clientIP =! machineIP:
						if 'Rennes' in machine_user[1]['zone']:
							update_campus(machine_user)
							messages.error(request, "Votre machine provient du campus de Rennes. Nous avons automatiquement modifié sa localisation dans notre LDAP. Veuillez renouveler votre adresse IP via DHCP (déconnectez vous du réseau puis reconnectez vous) afin d'obtenir un accès internet.")
						else:
							messages.error(request, "L'adresse IP que vous avez est différente de celle stockée pour la MAC {}. Veuillez utiliser un DHCP.".format(mac))
						
						return HttpResponseRedirect(reverse('fr:erreur'))

					else:
						machine_connue = True

						if 'Inactive' in machine_user[1]['zone']:
							return HttpResponseRedirect(reverse('fr:reactivation'))

						return render(request, 'fr/index_secure.html', context)

		return HttpResponseRedirect(reverse('fr:ajout_1'))

	return render(request, 'fr/index_secure.html', context)

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
				inscrire_user(uid)
				return HttpResponseRedirect(reverse('fr:index_secure'))

	else:
		form = AdhesionForm()
		
	context = {'form': form}
	return render(request, 'fr/devenir_membre.html', context)

@login_required(login_url='/fr/login')
def Ajout_1(request):
	mac = request.META['mac_client']
	uid = request.META['uid_client']
	request.META['alias_choisis'] =[]

	if request.POST:
		form = AliasForm(request.POST)

		if form.is_valid:
			for key, value in form.cleaned_data:
				if key == 'publiable':
					request.META['publiable'] = value
				else:
					if value != '':
						request.META['alias_choisis'].append(value)
			return HttpResponseRedirect(reverse('fr:ajout_2'))

	else:
		form = AliasForm()
		if mac == "aa:00:04:00:0a:04":
			messages.error(request, "ATTENTION ! Vous êtes visiblement victime du bug Debian <a href='http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=635604'>#635604</a>.Vous ne pourrez pas inscrire cette machine tant que l'adresse MAC ne sera pas rétablie. Veuillez contacter un administrateur ResEl.")
			return HttpResponseRedirect(reverse('fr:erreur'))

		alias = get_free_alias(uid)
		request.META['alias_auto'] = [alias]

		if messages.get_messages(request):
			return HttpResponseRedirect(reverse('fr:erreur'))

	context = {'form': form}

	return render(request, 'fr/ajout_1.html', context)

@login_required(login_url='/fr/login')
def Ajout_2(request):
	return render(request, 'fr/ajout_2.html')

@login_required(login_url='/fr/login')
def Ajout_3(request):
	ipHostNumber = get_free_ip(200, 223)
	lastdate = time.strftime('%Y%m%d%H%M%S')

	if request.META['nb_machines'] == 0:
		publiable = request.META['publiable']

	aliases = [request.META['alias_auto']]
	if len(request.META['alias_choisis']) != 0:
		for item in request.META['alias_choisis']:
			aliases.append(item)

	
	return render(request, 'fr/ajout_3.html')

















