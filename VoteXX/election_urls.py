"""
Helios URLs for Election related stuff

Ben Adida (ben@adida.net)
"""

from django.urls import path, re_path

from VoteXX import views
from VoteXX import election_url_names as names

urlpatterns = [

    re_path(r'^$', views.one_election, name=names.ELECTION_HOME),


    # election voting-process actions
    re_path(r'^/view$', views.one_election_view, name=names.ELECTION_VIEW),

    re_path(r'^/votetest$', views.vote_test, name=names.ELECTION_VOTETEST),
    re_path(r'^/bboard$', views.one_election_bboard, name=names.ELECTION_BBOARD),

]
