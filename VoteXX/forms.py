"""
Forms for Helios
"""



"""
Easy form for a Toy Election 
"""
from django import forms
from django.conf import settings

#from .fields import SplitDateTimeField
from .models import ToyElection
#from .widgets import SplitSelectDateTimeWidget


class ToyElectionForm(forms.Form):

    short_name = forms.SlugField(max_length=40,
                                 help_text='no spaces, will be part of the URL for your election, e.g. my-club-2010')
    name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'size': 60}),
                           help_text='the pretty name for your election, e.g. My Club 2010 Election')

    help_email = forms.CharField(required=False, initial="", label="Help Email Address",
                                 help_text='An email address voters should contact if they need help.')


class VoterForm(forms.Form):
    election_name = forms.SlugField(max_length=40,
                                    help_text='no spaces, will be part of the URL for your election, e.g. my-club-2010')

