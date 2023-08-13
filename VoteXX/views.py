from django.shortcuts import render, HttpResponse, redirect
import json
import sqlite3
import base64
import datetime
import logging
import os
import uuid
from urllib.parse import urlencode

from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction, IntegrityError
from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse

"""
minimal dependency for election_new
"""
from django.conf import settings

from .security import (can_create_election, get_voter ,get_election_by_uuid)
from VoteXX_auth.security import check_csrf, login_required, get_user, save_in_session_across_logouts
from .view_utils import SUCCESS, FAILURE, return_json, render_template, render_template_raw
from . import forms
from VoteXX import utils, VOTERS_EMAIL, VOTERS_UPLOAD, url_names



from .models import User, ToyElection, Voter
# Create your views here.



def toLogin_view(request):
    return render(request, 'login.html')

def election_view(request):

    from VoteXX import models

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        # res = {"user": None, "msg": None}
        s = request.POST.get("sid")
        e = request.POST.get("enc_data")
        o = request.POST.get("op_time")
        print(request.POST)

        dic = {'sid': s, 'enc_data': e, 'op_time': o}
        models.Flag.objects.create(**dic)
        # conn = sqlite3.connect("django.db")
        # c = conn.cursor()
        # sql1 = '''
        #     insert into VoteXX_flag(sid, enc_data, op_time)
        # '''
        # c.execute(sql1)
        # conn.commit()
        # conn.close()
    return render(request, 'election_page.html')



def election_new(request):
    if not can_create_election(request):
        return HttpResponseForbidden('only an administrator can create an election')

    error = None

    user = get_user(request)

    if request.method == "GET":
        election_form = forms.ToyElectionForm(initial={'help_email': user.info.get("email", '')})
    else:
        check_csrf(request)
        election_form = forms.ToyElectionForm(request.POST)

        if election_form.is_valid():
            # create the election obj
            election_params = dict(election_form.cleaned_data)

            # is the short name valid
            if utils.urlencode(election_params['short_name']) == election_params['short_name']:
                election_params['uuid'] = str(uuid.uuid1())

                user = get_user(request)
                election_params['admin'] = user
                try:
                    election = ToyElection.objects.create(**election_params)
                    return HttpResponseRedirect(
                        settings.SECURE_URL_HOST + reverse(url_names.election.ELECTION_VIEW, args=[election.uuid]))
                except IntegrityError:
                    error = "An election with short name %s already exists" % election_params['short_name']
            else:
                error = "No special characters allowed in the short name."

    return render_template(request, "election_new", {'election_form': election_form, 'error': error})


"""
copy from helios
"""

@return_json
def one_election(request, election):
    if not election:
        raise Http404
    return election.toJSONDict(complete=True)

@return_json
def one_election_meta(request, election):
    if not election:
        raise Http404
    return election.metadata


def get_election_url(election):
    return settings.URL_HOST + reverse(url_names.ELECTION_SHORTCUT, args=[election.short_name])

def election_shortcut(request, election_short_name):
    election = ToyElection.get_by_short_name(election_short_name)
    if election:
        return HttpResponseRedirect(settings.SECURE_URL_HOST + reverse(url_names.election.ELECTION_VIEW, args=[election.uuid]))
    else:
        raise Http404



def get_election_badge_url(election):
    return settings.URL_HOST + reverse(url_names.election.ELECTION_BADGE, args=[election.uuid])


def one_election_view(request, election_uuid):
    user = get_user(request)

    election = get_election_by_uuid(election_uuid)

    # election_url = get_election_url(election)
    # election_badge_url = get_election_badge_url(election)
    status_update_message = None

    vote_url = "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urlencode(
        {'election_url': reverse(url_names.election.ELECTION_HOME, args=[election.uuid])}))

    # test_cookie_url = "%s?%s" % (reverse(url_names.COOKIE_TEST), urlencode({'continue_url': vote_url}))

    if user:
        voter = Voter.get_by_election_and_user(election, user)
    else:
        voter = get_voter(request, user, election)

    # if voter:
    #     # cast any votes?
    #     votes = CastVote.get_by_voter(voter)
    # else:
    #     votes = None

    # should we show the result?
    # show_result = election.result_released_at or election.result

    return render_template(request, 'election_view',
                           {'election': election, 'user': user,
                            'voter': voter,
                            'vote_url': vote_url,})
