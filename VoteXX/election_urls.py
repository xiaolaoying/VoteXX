"""
Helios URLs for Election related stuff

Ben Adida (ben@adida.net)
"""

from django.urls import path, re_path

from VoteXX import views
from VoteXX import election_url_names as names

urlpatterns = [

    path('', views.one_election, name=names.ELECTION_HOME),


    # election voting-process actions
    path('view/', views.one_election_view, name=names.ELECTION_VIEW),

    path('votetest/', views.vote_test, name=names.ELECTION_VOTETEST),
    path('bboard/', views.one_election_bboard, name=names.ELECTION_BBOARD),

]
