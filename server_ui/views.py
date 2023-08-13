
import copy

from django.shortcuts import render, HttpResponse
from django.conf import settings

import VoteXX_auth.views as auth_views
from VoteXX.models import ToyElection
from VoteXX.security import can_create_election
from VoteXX_auth.security import get_user
#from . import glue
from .view_utils import render_template
# Create your views here.


def home(request):
    # load the featured elections
    # featured_elections = ToyElection.get_featured()

    user = get_user(request)
    create_p = can_create_election(request)

    if create_p:
        elections_administered = ToyElection.get_by_user_as_admin(user, archived_p=False, limit=20)
    else:
        elections_administered = None
    #
    # if user:
    #     elections_voted = ToyElection.get_by_user_as_voter(user, limit=5)
    # else:
    #     elections_voted = None

    auth_systems = copy.copy(settings.AUTH_ENABLED_SYSTEMS)
    # try:
    #     auth_systems.remove('password')
    # except:
    #     pass

    login_box = auth_views.login_box_raw(request, return_url="/", auth_systems=auth_systems)

    # return render_template(request, "index", {'elections': featured_elections,
    #                                           'elections_administered': elections_administered,
    #                                           'elections_voted': elections_voted,
    #                                           'create_p': create_p,
    #                                           'login_box': login_box})

    return render_template(request, "index", {'create_p': create_p,
                                              'elections_administered': elections_administered,
                                              'login_box': login_box})

