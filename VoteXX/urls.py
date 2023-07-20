from django.urls import path

from . import views

# app_name = VoteXX

urlpatterns = [
    path('login/', views.toLogin_view, name='toLogin'),
    path('election/', views.election_view, name='election_page'),
]
