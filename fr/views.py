#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout
from django.core.mail import mail_admins, EmailMessage
from django.utils.six.moves import urllib_parse
from django.contrib.auth import REDIRECT_FIELD_NAME

import re
import time
from datetime import datetime
import binascii, hashlib

from .network import *
from .ldap_func import *
from .forms import AdhesionForm, AliasForm, ContactForm

def Login_LDAP(request, next_page=None):
    """ Affiche le formulaire de login LDAP et redirige vers la bonne page """

    if next_page == None:
        next_page = request.GET.get(REDIRECT_FIELD_NAME)
        if next_page == None:
            next_page = request.META.get('HTTP_REFERER', '/fr/index')
            prefix = urllib_parse.urlunparse(
                ('https', request.get_host(), '', '', '', ''),
            )
            if next_page.startswith(prefix):
                next_page = next_page[len(prefix):]

    if request.user.is_authenticated():
        return HttpResponseRedirect(next_page)

    request.session['LDAP'] = True

    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            auth_login(request, form.get_user())
            request.session['uid_client'] = str(request.user.username)

            return HttpResponseRedirect(reverse('fr:index'))
    else:
        form = AuthenticationForm(request)

    context = {
        'form': form,
    }

    return render(request, 'fr/login_ldap.html', context)

@login_required(login_url='/')
def Logout_LDAP(request):
    """ Déconnecte l'user et le bascule vers un message de succès """
    if 'LDAP' in request.session:
        logout(request)
        return render(request, 'fr/logout_ldap.html')

    else:
        return HttpResponseRedirect(reverse('fr:logout_cas'))

@login_required(login_url='/')
def Erreur(request):
    """ Template générique servant à afficher une éventuelle erreur en cours de process """

    return render(request, 'fr/erreur.html')

@login_required(login_url='/')
def Index(request):
    """ Accueil """

    clientIP = request.META['HTTP_X_FORWARDED_FOR']
    machineInactive = False

    if re.search('172.23.', clientIP): # On bascule vers inscription.rennes si l'user se connecte de Rennes
        return redirect('http://inscription.rennes.resel.fr')

    if re.search('172.22.(20{1,3}|21{1,3}|220|221|222|223|224|225)', clientIP) is None:
        messages.error(request, 'Votre IP ne correspond pas à une IP du type 172.22.22(4-5).Y ; Veuillez configurer votre carte réseau pour obtenir une IP via DHCP.')
        return HttpResponseRedirect(reverse('fr:erreur'))

    if clientIP != "172.22.42.4" and inactive(get_mac_from_ip(request, clientIP, '22')): # Vérification que la machine est active
        machineInactive = True

    if messages.get_messages(request):
        return HttpResponseRedirect(reverse('fr:erreur'))

    if search("ou=people,dc=maisel,dc=enst-bretagne,dc=fr" , "(uid={})".format(str(request.user))) is None:
        """ La personne n'est pas encore présente dans le LDAP, donc on l'ajoute """
        return HttpResponseRedirect(reverse('fr:devenir_membre'))

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

            mail_admins("[Inscription Brest] Problemes rencontres sur inscription.resel.fr", "Utilisateur : {} {}\nBâtiment : {}\nChambre : {}\n\nSujet : {}\n\nDescription :\n{}\n\nContact : {}".format(prenom, nom.upper(), batiment, chambre, sujet, description, mail), fail_silently=False, connection=None, html_message=None)

            mail_envoye = True
    else:
        mail_envoye = False
        form = ContactForm()

    context = {
        'form': form,
        'mail_envoye': mail_envoye
    }

    return render(request, 'fr/contact.html', context)

@login_required(login_url='/')
def Inscription(request):
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
                3) enfin, si toutes les vérifs sont faites, l'user est juste en visite sur le site, du coup on renvoie vers la page d'index
            ° si non, on le bascule vers la vue Ajout_1
    """

    clientIP = request.META['HTTP_X_FORWARDED_FOR']
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

            machine_user = search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAdress={})".format(mac))

            if machine_user:
                machine_user = machine_user[0]
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

                        return HttpResponseRedirect(reverse('fr:index'))

        return HttpResponseRedirect(reverse('fr:ajout_1'))

    else:
        return HttpResponseRedirect(reverse('fr:devenir_membre'))

@login_required(login_url='/')
def Reactivation(request):
    """ Vue pour réactiver la machine """

    clientIP = request.META['HTTP_X_FORWARDED_FOR']
    mac = get_mac_from_ip(request, clientIP, '22')

    if messages.get_messages(request):
        return HttpResponseRedirect(reverse('fr:erreur'))

    machine = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )

    if machine:
        machine = machine[0]
        if 'Inactive' not in machine[1]['zone'] :
            messages.error(request, "Votre machine n'est pas inactive.")
            return HttpResponseRedirect(reverse('fr:erreur'))

        mod_attrs = [
            ( ldap.MOD_DELETE, 'zone', 'Inactive' ),
            ( ldap.MOD_ADD, 'zone', 'Brest' )
        ]
        
        mod(machine[0], mod_attrs)
        update_dhcp_dns_firewall()

        return render(request, 'fr/reactivation.html')

    else:
        messages.error(request, "Votre machine n'est pas encore connue sur notre réseau.")
        return HttpResponseRedirect(reverse('fr:erreur'))

@login_required(login_url='/')
def Devenir_membre(request):
    """ Vue appelée pour que l'user s'inscrive au ResEl
        C'est cette vue qui créer la fiche LDAP de l'user
        On lui affiche le réglement intérieur, et un formulaire pour remplir les champs LDAP
    """
    context = {}

    if search("ou=people,dc=maisel,dc=enst-bretagne,dc=fr" , "(uid={})".format(str(request.user))):
        messages.error(request, "Vous êtes déjà membre du ResEl.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    if request.method == 'POST':
        form = AdhesionForm(request.POST)

        if form.is_valid():
            personne = search_ecole(str(request.user))
            firstname = personne['gecos'][0].split(' ')[0]
            lastname = personne['gecos'][0].split(' ')[1]
            password = form.cleaned_data['userPassword']

            year = datetime.now().year
            month = datetime.now().month

            if month < 6:
                year -= 1

            add_record = [ 
                ('uid', [str(request.user)]),
                ('firstname', [firstname]),
                ('lastname', [lastname]),
                ('mail', [personne['mail'][0]]),
                ('anneeScolaire', ["{}/{}".format(year, year+1)]),
                ('dateInscr', [time.strftime('%Y%m%d%H%M%S') + 'Z']),
                ('objectClass', ['genericPerson','enstbPerson','reselPerson', 'maiselPerson']),
                ('campus', ['Brest']),
            ]

            """ Mots de passe """
            # Génération du NTLM Hash pour le mdp wifi
            ntPassword = binascii.hexlify(hashlib.new('md4', password.encode('utf-16le')).digest()).upper()

            # Génération du hash pour le mdp user
            userPassword = hashPassword(password)

            add_record.append( ('userPassword', [userPassword]) )
            add_record.append( ('ntPassword', [ntPassword]) )

            # Attribut formation
            formation = form.cleaned_data['formation']
            add_record.append( ('formation', [str(formation)]) )

            # Attribut promo
            if formation == "IG1A":
                promo = year + 3
            elif formation == "IG2A":
                promo = year + 2
            elif formation == "IG3A":
                promo = year + 1
            else:
                promo = year + 3
            add_record.append( ('promo', [str(promo)]) )

            # Attribut publiable
            if form.cleaned_data['publiable']:
                add_record.append( ('publiable', ['TRUE']))
            else:
                add_record.append( ('publiable', ['FALSE']))

            # Attributs optionnels
            if form.cleaned_data['birthdate']:
                add_record.append( ('birthdate', [str(form.cleaned_data['birthdate'] + '000000Z')]))

            if form.cleaned_data['batiment']:
                add_record.append( ('batiment', [str(form.cleaned_data['batiment'])]))
            else:
                add_record.append( ('batiment', ['0']))

            if form.cleaned_data['roomNumber']:
                add_record.append( ('roomNumber', [str(form.cleaned_data['roomNumber'])]))
            else:
                add_record.append( ('roomNumber', ['0']))

            if form.cleaned_data['mobile']:
                add_record.append( ('mobile', [str(form.cleaned_data['mobile'])]))
            else:
                add_record.append( ('mobile', ['0']))

            # Ajout de la fiche LDAP
            add_entry("uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr".format(str(request.user)), add_record)
            context['ajout_fait'] = True

            return render(request, 'fr/devenir_membre.html', context)

    else:
        form = AdhesionForm()
        context['ajout_fait'] = False

    context['form'] = form

    return render(request, 'fr/devenir_membre.html', context)

@login_required(login_url='/')
def Ajout_1(request):
    """ 
        Vue pour ajouter une machine au DN de l'user
        On récupère ici les éventuels alias perso choisis par l'user, et si il souhaite que ses infos persos soit publiables dans l'annuaire ResEl ou non
        On bascule ensuite vers Ajout_2
    """
    if 'mac_client' in request.session:
        mac = request.session['mac_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre adresse MAC. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    machine = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )
    if machine:
        messages.error(request, "Votre machine est déjà enregistrée sur notre réseau.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    if 'uid_client' in request.session:
        uid = request.session['uid_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre uid. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    request.session['alias_choisis'] =[]

    if request.POST:
        form = AliasForm(request.POST)

        if form.is_valid():
            if form.cleaned_data['alias1']:
                request.session['alias_choisis'].append(form.cleaned_data['alias1'])

            if form.cleaned_data['alias2']:
                request.session['alias_choisis'].append(form.cleaned_data['alias2'])

            return HttpResponseRedirect(reverse('fr:ajout_2'))

    else:
        form = AliasForm()
        if mac == "aa:00:04:00:0a:04":
            messages.error(request, "ATTENTION ! Vous êtes visiblement victime du bug Debian <a href='http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=635604'>#635604</a>.Vous ne pourrez pas inscrire cette machine tant que l'adresse MAC ne sera pas rétablie. Veuillez contacter un administrateur ResEl.")
            return HttpResponseRedirect(reverse('fr:erreur'))

        alias = get_free_alias(uid)
        request.session['alias_auto'] = alias

        if messages.get_messages(request):
            return HttpResponseRedirect(reverse('fr:erreur'))

    context = {
        'form': form,
    }

    return render(request, 'fr/ajout_1.html', context)

@login_required(login_url='/')
def Ajout_2(request):
    """
        Rien de bien folichon ici, on affiche les alias de la machine, et on demande à l'user de continuer vers la vue Ajout_3
    """
    if request.session['mac_client']:
        mac = request.session['mac_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre adresse MAC. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    machine = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )
    if machine:
        messages.error(request, "Votre machine est déjà enregistrée sur notre réseau.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    return render(request, 'fr/ajout_2.html')

@login_required(login_url='/')
def Ajout_3(request):
    """
        Ici on crée la fiche LDAP de la machine, on l'ajoute au DN de l'user, et on reboot DHCP, DNS et FW
    """
    if request.session['mac_client']:
        mac = request.session['mac_client']
    else:
        messages.error(request, "Une erreur est survenue dans la récupération de votre adresse MAC. Veuillez réessayer.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    machine = search( "ou=machines,dc=resel,dc=enst-bretagne,dc=fr" , "(macAddress={})".format(mac) )
    if machine:
        messages.error(request, "Votre machine est déjà enregistrée sur notre réseau.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    ip = get_free_ip(200, 223)
    lastdate = time.strftime('%Y%m%d%H%M%S') + 'Z'

    # Ici on gère les alias : si aucun choisi, on met un 0 devant l'alias auto en guise de hostAlias, pour pas faire planter le DNS au reboot
    # C'est caca, faut corriger dans le script DNS mais en attendant... :D
    if len(request.session['alias_choisis']) == 0: 
        hostname = str(request.session['alias_auto'])
        aliases = ['0' + hostname]
    elif len(request.session['alias_choisis']) == 1:
        hostname = str(request.session['alias_choisis'][0])
        aliases = [str(request.session['alias_auto'])]
    else:
        hostname = str(request.session['alias_choisis'][0])
        aliases = [str(request.session['alias_auto']), str(request.session['alias_choisis'][1])]

    add_record = [
        ('objectClass', ['reselMachine']),
        ('host', [hostname]),
        ('uidproprio', ['uid={},ou=people,dc=maisel,dc=enst-bretagne,dc=fr'.format(request.session['uid_client'])]),
        ('iphostnumber', [str(ip)]),
        ('macaddress', [str(request.session['mac_client'])]),
        ('zone', ['Brest', 'User']),
        ('hostalias', aliases),
        ('lastdate', [lastdate])
    ]

    # Dernières vérif avant d'ajouter la machine
    if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(iphostnumber={})".format(ip)) is not None:
        messages.error(request, "L'adresse IP censée vous être attribuée n'est plus disponible. Recommencez la procédure pour régler ce problème.")
        return HttpResponseRedirect(reverse('fr:erreur'))

    if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(host={})".format(hostname)) is None:
        add_entry("host={},ou=machines,dc=resel,dc=enst-bretagne,dc=fr".format(hostname), add_record)
        mail = EmailMessage(
                subject="[Inscription Brest] Machine {} [172.22.{} - {}] par {}".format(hostname, ip, request.session['mac_client'], request.session['uid_client']),
                body="Inscription de la machine {} appartenant à {}\n\nIP : 172.22.{}\nMAC : {}".format(hostname, request.session['uid_client'], ip, request.session['mac_client']),
                from_email="inscription-bot@resel.fr",
                reply_to=["inscription-bot@resel.fr"],
                to=["inscription-bot@resel.fr", "botanik@resel.fr"],
                headers={'Cc': 'botanik@resel.fr'}
            )
        mail.send()
    else:
        messages.error(request, "L'host {} existe déjà dans le LDAP ResEl, veuillez recommencer la procédure.".format(hostname))
        return HttpResponseRedirect(reverse('fr:erreur'))

    update_dhcp_dns_firewall()

    return render(request, 'fr/ajout_3.html')

















