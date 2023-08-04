from django.urls import path,re_path

from . import views, url_names

from djangoProject.settings import AUTH_ENABLED_SYSTEMS
# app_name = VoteXX

urlpatterns = [
    # basic static stuff
    path('', views.index, name=url_names.AUTH_INDEX),
    path('logout/', views.logout, name=url_names.AUTH_LOGOUT),
    re_path(r'^start/(?P<system_name>.*)$', views.start, name=url_names.AUTH_START),
    # weird facebook constraint for trailing slash
    path('after/', views.after, name=url_names.AUTH_AFTER),
    path('why/', views.perms_why, name=url_names.AUTH_WHY),
    path('after_intervention/', views.after_intervention, name=url_names.AUTH_AFTER_INTERVENTION),
]

# password auth
if 'password' in AUTH_ENABLED_SYSTEMS:
    from .auth_systems.password import urlpatterns as password_patterns
    urlpatterns.extend(password_patterns)