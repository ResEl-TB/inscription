#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.conf.urls import patterns, url

from . import views

urlpatterns = [
	url(r'^login_ldap$', views.Login_LDAP, {'LDAP': True}, name='login_ldap'),
	url(r'^login_cas$', 'django_cas_ng.views.login', {'next_page': '/en/index'}),
    url(r'^logout_cas$', 'django_cas_ng.views.logout'),
	url(r'^index$', views.Index, name='index'), # Vue appelée lorsque tout est en règle
	url(r'^error$', views.Erreur, name='error'), # Vue appelée lorsque qu'une erreur est soulevée
	url(r'^contact$', views.Contact, name="contact"), # Vue pour afficher un formulaire d'envoi de mail pour nous contacter
	url(r'^inscription$', views.Inscription, name='inscription'), # Vue de l'index APRES login
	url(r'^add/1$', views.Ajout_1, name='add_1'), # Vue pour ajouter une machine au LDAP, étape 1
	url(r'^add/2$', views.Ajout_2, name='add_2'), # Vue pour ajouter une machine au LDAP, étape 2
	url(r'^add/3$', views.Ajout_3, name='add_3'), # Vue pour ajouter une machine au LDAP, étape 3
	url(r'^reactivation$', views.Reactivation, name='reactivation'), # Vue pour réactiver une machine
	url(r'^register$', views.Devenir_membre, name='register'), # Vue pour devenir membre du ResEl
]
