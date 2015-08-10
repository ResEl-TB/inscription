#!/usr/local/bin/python
# -*- coding: utf-8 -*-

from django.conf.urls import patterns, url

from . import views

urlpatterns = [
	url(r'^$', views.Verification, name='verification'), # Vue d'accueil, qui teste si on a bien une IP ResEl...
	url(r'^index$', views.Index, name='index'), # Vue appelée lorsque tout est en règle
	url(r'^erreur$', views.Erreur, name='erreur'), # Vue appelée lorsque qu'une erreur est soulevée
	url(r'^login$', views.Login,  name='login'), # Vue appelée pour se logger
	url(r'^index_secure$', views.Index_secure, name='index_secure'), # Vue de l'index APRES login
	url(r'^ajout/1$', views.Ajout, name='ajout_1'), # Vue pour ajouter une machine au LDAP, étape 1
	url(r'^ajout/2$', views.Ajout, name='ajout_2'), # Vue pour ajouter une machine au LDAP, étape 2
	url(r'^ajout/3$', views.Ajout, name='ajout_3'), # Vue pour ajouter une machine au LDAP, étape 3
	url(r'^reactivation$', views.Reactivation, name='reactivation'), # Vue pour réactiver une machine
	url(r'^devenir_membre$', views.Devenir_membre, name='devenir_membre'), # Vue pour devenir membre du ResEl
]
