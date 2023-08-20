from django.urls import path, re_path, include

from . import views, url_names as names

# app_name = VoteXX

urlpatterns = [
    # path('login/', views.toLogin_view, name='toLogin'),
    path('test/', views.test, name='election_page'),

    # election
    # re_path(r'^elections/params$', views.election_params, name=names.ELECTIONS_PARAMS),
    # re_path(r'^elections/verifier$', views.election_verifier, name=names.ELECTIONS_VERIFIER),
    # re_path(r'^elections/single_ballot_verifier$', views.election_single_ballot_verifier,
    #     name=names.ELECTIONS_VERIFIER_SINGLE_BALLOT),
    # re_path(r'^elections/new$', views.election_new, name=names.ELECTIONS_NEW),
    # re_path(r'^elections/administered$', views.elections_administered, name=names.ELECTIONS_ADMINISTERED),
    # re_path(r'^elections/voted$', views.elections_voted, name=names.ELECTIONS_VOTED),
    #
    # re_path(r'^elections/(?P<election_uuid>[^/]+)', include('VoteXX.election_urls')),

    re_path(r'^elections/new$', views.election_new, name=names.ELECTIONS_NEW),

    re_path(r'^elections/voted$', views.elections_voted, name=names.ELECTIONS_VOTED),

    re_path(r'^elections/(?P<election_uuid>[^/]+)/', include('VoteXX.election_urls')),
]
