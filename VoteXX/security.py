"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

"""
This is a minimal version for VoteXX security
only for election create test
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""

import urllib.parse
# nicely update the wrapper function
from functools import update_wrapper

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.http import HttpResponseRedirect
from django.urls import reverse

import VoteXX
from VoteXX_auth.security import get_user
from .models import Voter, ToyElection


class HSTSMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        if settings.STS:
            response['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"
        return response



def can_create_election(request):
    user = get_user(request)
    if not user:
        return False

    # if VoteXX.ADMIN_ONLY:
    #     return user.admin_p
    # else:
    #     return user.can_create_election()
    return user.can_create_election()


def get_voter(request, user, election):
    """
    return the current voter
    """
    voter = None
    if 'CURRENT_VOTER_ID' in request.session:
        voter = Voter.objects.get(id=request.session['CURRENT_VOTER_ID'])
        if voter.election != election:
            voter = None

    if not voter:
        if user:
            voter = Voter.get_by_election_and_user(election, user)

    return voter


def get_election_by_uuid(uuid):
    if not uuid:
        raise Exception("no election ID")

    return ToyElection.get_by_uuid(uuid)


def election_view(**checks):
    def election_view_decorator(func):
        def election_view_wrapper(request, election_uuid=None, *args, **kw):
            election = get_election_by_uuid(election_uuid)

            if not election:
                raise Http404

            # do checks
            # do_election_checks(election, checks)

            # if private election, only logged in voters
            # if election.private_p and not checks.get('allow_logins', False):
            #     from .views import password_voter_login
            #     if not user_can_see_election(request, election):
            #         return_url = request.get_full_path()
            #         return HttpResponseRedirect(
            #             "%s?%s" % (reverse(password_voter_login, args=[election.uuid]), urllib.parse.urlencode({
            #                 'return_url': return_url
            #             })))

            return func(request, election, *args, **kw)

        return update_wrapper(election_view_wrapper, func)

    return election_view_decorator

