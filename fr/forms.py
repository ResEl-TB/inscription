#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import re
from ldap_func import search
from django import forms

class AdhesionForm(forms.Form):
	accepted = forms.BooleanField()

class AliasForm(forms.Form):
	alias_1 = forms.CharField(required=False, max_length=25)
	alias_2 = forms.CharField(required=False, max_length=25)
	publiable = forms.BooleanField(required=False)

	# Test si les alias fourni sont valides
	def clean_alias_1(self):
		alias = self.cleaned_data['alias_1']

		if re.search(r'^[a-z][a-z0-9-]{0,23}[a-z0-9]', alias) is None:
			raise forms.ValidationError("L'alias {} ne correspond pas à la forme attendue.".format(alias))
		else:
			if re.search(r'enst-bretagne', alias):
				raise forms.ValidationError("L'alias ne doit pas contenir le nom de l'école.")
			if re.search(r'resel', alias)
				raise forms.ValidationError("L'alias ne doit pas contenir le nom resel.")
			if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(hostAlias={}".format(alias)) is None:
				raise forms.ValidationError("L'alias choisi est déjà utilisé pour une machine de notre réseau.")
		return alias

	def clean_alias_2(self):
		alias = self.cleaned_data['alias_2']

		if re.search(r'^[a-z][a-z0-9-]{0,23}[a-z0-9]', alias) is None:
			raise forms.ValidationError("L'alias {} ne correspond pas à la forme attendue.".format(alias))
		else:
			if re.search(r'enst-bretagne', alias):
				raise forms.ValidationError("L'alias ne doit pas contenir le nom de l'école.")
			if re.search(r'resel', alias)
				raise forms.ValidationError("L'alias ne doit pas contenir le nom resel.")
			if search("ou=machines,dc=resel,dc=enst-bretagne,dc=fr", "(hostAlias={}".format(alias)) is None:
				raise forms.ValidationError("L'alias choisi est déjà utilisé pour une machine de notre réseau.")
		return alias