#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.conf.urls import patterns, url

from . import views

urlpatterns = [
	url(r'^login_ldap$', views.Login_LDAP, name='login_ldap'),
	url(r'^logout_ldap$', views.Logout_LDAP, name='logout_ldap'),
	url(r'^login_cas$', 'django_cas_ng.views.login', {'next_page': '/fr/index'}, name="login_cas"),
    url(r'^logout_cas$', 'django_cas_ng.views.logout', name="logout_cas"),
	url(r'^index$', views.Index, name='index'), # Vue d'accueil
	url(r'^erreur$', views.Erreur, name='erreur'), # Vue appelée lorsque qu'une erreur est soulevée
	url(r'^contact$', views.Contact, name="contact"), # Vue pour afficher un formulaire d'envoi de mail pour nous contacter
	url(r'^inscription$', views.Inscription, name='inscription'), # Vue qui gère les redirections lors d'une tentative d'inscription de machine
	url(r'^ajout/1$', views.Ajout_1, name='ajout_1'), # Vue pour ajouter une machine au LDAP, étape 1
	url(r'^ajout/2$', views.Ajout_2, name='ajout_2'), # Vue pour ajouter une machine au LDAP, étape 2
	url(r'^ajout/3$', views.Ajout_3, name='ajout_3'), # Vue pour ajouter une machine au LDAP, étape 3
	url(r'^reactivation$', views.Reactivation, name='reactivation'), # Vue pour réactiver une machine
	url(r'^devenir_membre$', views.Devenir_membre, name='devenir_membre'), # Vue pour devenir membre du ResEl
	url(r'^resel_person$', views.Resel_person, name='resel_person'),
]
