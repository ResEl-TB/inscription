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
from .forms import AdhesionForm, AliasForm, ContactForm
from .models import Profil

def Verification(request):
    """ Vérif que le client est dans le bon subnet """

    clientIP = request.META['REMOTE_ADDR']
    request.session['mac_client'] = None

    if re.search('172.22.(20{1,3}|21{1,3}|220|221|222|223|224|225)', clientIP):
        return HttpResponseRedirect(reverse('fr:index'))
        
    else:
        messages.error(request, 'Votre IP ne correspond pas à une IP du type 172.22.22(4-5).Y ; Veuillez configurer votre carte réseau pour obtenir une IP via DHCP.')
        return HttpResponseRedirect(reverse('fr:erreur'))

def Erreur(request):
    """ Template générique servant à afficher une éventuelle erreur en cours de process """

    return render(request, 'fr/erreur.html')

def Index(request):
    """ Index lorsque le client n'est pas loggé """

    clientIP = request.META['REMOTE_ADDR']
    machineInactive = False

    if clientIP.split('.')[1] == '23': # On bascule vers inscription.rennes si l'user se connecte de Rennes
        return redirect('http://inscription.rennes.resel.fr')

    if clientIP != "172.22.42.4" and inactive(get_mac_from_ip(request, clientIP, '22')): # Vérification que la machine est active
        machineInactive = True

    if messages.get_messages(request):
        return HttpResponseRedirect(reverse('fr:erreur'))

    return render(request, 'fr/index.html', {'machineInactive': machineInactive})

def Contact(request):
    """ Affiche un formulaire de contact """

    if request.method == 'POST':
        form = ContactForm(request.POST)

        if form.is_valid():
            nom = form.cleaned_data['nom']
            prenom = form.cleaned_data['prenom']
            mail = form.cleaned_data['mail']
            batiment = form.cleaned_data['batiment']
            chambre = form.cleaned_data['chambre']
            sujet = form.cleaned_data['sujet']
            description = form.cleaned_data['description']

            mail_admins("[Inscription Brest] {}".format(sujet), "L'user {0} {1} habitant au {2} {3} rencontre des problemes sur inscription.resel.fr \n Sujet : {4} \n Description :\n {5} \n\n Il faut le recontacter à l'adresse {6}".format(nom, prenom, batiment, chambre, sujet, description, mail), fail_silently=False, connection=None, html_message=None)

            mail_envoye = True
    else:
        mail_envoye = False
        form = ContactForm()

    context = {
        'form': form,
        'mail_envoye': mail_envoye
    }

    return render(request, 'fr/contact.html', context)

def Login(request):
    """ Affiche le formulaire de login et redirige vers la bonne page """

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())
            request.session['uid_client'] = str(request.user.username)

            return HttpResponseRedirect(reverse('fr:index_secure'))
    else:
        form = AuthenticationForm(request)

    context = {
        'form': form,
    }

    return render(request, 'fr/login.html', context)

@login_required(login_url='/fr/login')
def Index_secure(request):
    """ Index juste après un login réussi. 
        Effectue toutes les vérifs nécessaires :
        - l'user est-il blacklisté ?
        - l'user est-il genericPerson, enstbPerson, guestPerson ?
        - si l'user n'est pas reselPerson, on le redirige vers la vue Devenir_membre pour qu'il le devienne
        - s'il l'est, on regarde si la machine de l'user est présente dans le ldap :
            ° si oui :  
                1) on vérifie que l'user est le proprio enregistré. Si ce n'est pas le cas, les admins sont prévenus 
                2) ensuite on vérifie que l'ip de l'user correspond à l'ip enregistrée dans le ldap.
                   Si c'est non, on check si il vient d'un campus différent, auquel cas on update automatiquement sa fiche ldap et on lui dit de reset sa connexion
                   Si il ne vient pas d'un campus différent, on lui dit de passer par un DHCP
                3) enfin, si toutes les vérifs sont faites, l'user est juste en visite sur le site, du coup on display la page index_secure
            ° si non, on le bascule vers la vue Ajout_1
    """

    clientIP = request.META['REMOTE_ADDR']
    mac = get_mac_from_ip(request, clientIP, '22')
    uid = str(request.user.username)
    statuts = get_status(request, uid)
    machine_connue = False
    
    if messages.get_messages(request):
        return HttpResponseRedirect(reverse('fr:erreur'))

    request.session['uid_client'] = uid
    request.session['mac_client'] = mac

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
        request.session['nb_machines'] = 0
        context['inscrit_resel'] = True
        machines = search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(uidProprio=uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr)".format(uid))

        if machines:
            context['machines'] = machines
            request.session['nb_machines'] = len(machines)

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

                    if clientIP != machineIP:
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

    else:
        return HttpResponseRedirect(reverse('fr:devenir_membre'))

    return render(request, 'fr/index_secure.html', context)

@login_required(login_url='/fr/login')
def Reactivation(request):
    """ Vue pour réactiver la machine """

    if request.session['mac_client']:
        mac = request.session['mac_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre adresse MAC. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))
    machine = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )[0]

    if 'Brest' in machine[1]['zone'] :
        messages.error(request, "Votre machine n'est pas inactive.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    mod_attrs = [
        ( ldap.MOD_DELETE, 'zone', 'Inactive' ),
        ( ldap.MOD_ADD, 'zone', 'Brest' )
    ]

    mod(machine[0], mod_attrs)
    update_dhcp_dns_firewall()

    return render(request, 'fr/reactivation.html')

@login_required(login_url='/fr/login')
def Devenir_membre(request):
    """ Vue appelée pour que l'user devienne reselPerson 
        On lui affiche le réglement intérieur, et la checkbox pour dire "oui oui, j'ai rien lu file moi ma co !"
    """
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
    """ 
        Vue pour ajouter une machine au DN de l'user
        On récupère ici les éventuels alias perso choisis par l'user, et si il souhaite que ses infos persos soit publiables dans l'annuaire ResEl ou non
        On bascule ensuite vers Ajout_2
    """
    if request.session['mac_client']:
        mac = request.session['mac_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre adresse MAC. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    if request.session['uid_client']:
        uid = request.session['uid_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre uid. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    request.session['alias_choisis'] =[]

    if request.POST:
        form = AliasForm(request.POST)

        if form.is_valid:
            for key, value in form.cleaned_data:
                if key == 'publiable':
                    request.session['publiable'] = value
                else:
                    if value != '':
                        request.session['alias_choisis'].append(value)
            return HttpResponseRedirect(reverse('fr:ajout_2'))

    else:
        form = AliasForm()
        if mac == "aa:00:04:00:0a:04":
            messages.error(request, "ATTENTION ! Vous êtes visiblement victime du bug Debian <a href='http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=635604'>#635604</a>.Vous ne pourrez pas inscrire cette machine tant que l'adresse MAC ne sera pas rétablie. Veuillez contacter un administrateur ResEl.")
            return HttpResponseRedirect(reverse('fr:erreur'))

        alias = get_free_alias(uid)
        request.session['alias_auto'] = [alias]

        if messages.get_messages(request):
            return HttpResponseRedirect(reverse('fr:erreur'))

    context = {
        'form': form,
    }

    return render(request, 'fr/ajout_1.html', context)

@login_required(login_url='/fr/login')
def Ajout_2(request):
    """
        Rien de bien folichon ici, on affiche les alias de la machine, et on demande à l'user de continuer vers la vue Ajout_3
    """
    return render(request, 'fr/ajout_2.html', context)

@login_required(login_url='/fr/login')
def Ajout_3(request):
    """
        Ici on crée la fiche LDAP de la machine, on l'ajoute au DN de l'user, et on reboot DHCP, DNS et FW
    """
    ip = get_free_ip(200, 223)
    lastdate = time.strftime('%Y%m%d%H%M%S') + 'Z'

    # Ici on gère les alias : si aucun choisi, on met un 0 devant l'alias auto en guise de hostAlias, pour pas faire planter le DNS au reboot
    # C'est caca, faut corriger dans le script DNS mais en attendant... :D
    if len(request.session['alias_choisis']) == 0: 
        hostname = request.session['alias_auto']
        aliases = ['0' + hostname]
    elif len(request.session['alias_choisis']) == 1:
        hostname = request.session['alias_choisis'][0]
        aliases = [request.session['alias_auto']]
    else:
        hostname = request.session['alias_choisis'][0]
        aliases = [request.session['alias_auto'], request.session['alias_choisis'][1]]

    add_record = [
        ('objectClass', ['reselMachine']),
        ('host', [hostname]),
        ('uidproprio', ['uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr'.format(request.session['uid_client'])]),
        ('iphostnumber', [str(ip)]),
        ('macaddress', [request.session['mac_client']]),
        ('zone', ['Brest', 'User']),
        ('hostalias', aliases),
        ('lastdate', [lastdate])
    ]

    add_entry("host={},ou=machines,dc=resel,dc=enst-bretagne,dc=fr".format(hostname), add_record)

    # Modification du champ publiable si c'est la premiere machine
    if request.session['nb_machines'] == 0:
        publiable = request.session['publiable']

        personne = search("ou=people,dc=maisel,dc=enst-bretagne,dc=fr","(uid={})".format(request.session['uid_client']))[0]
        if 'maiselPerson' in personne[1]['objectClass']:
            mod_attrs = [
                ( ldap.MOD_REPLACE, 'publiable', publiable )
            ]
            mod("uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr".format(request.session['uid_client']), mod_attrs)

    update_dhcp_dns_firewall()

    return render(request, 'fr/ajout_3.html')

















