from django import forms

class AdhesionForm(forms.Form):
	accepted = forms.BooleanField()