#from . import password, github
from . import password

AUTH_SYSTEMS = {}

AUTH_SYSTEMS['password'] = password
#AUTH_SYSTEMS['github'] = github

def can_check_constraint(auth_system):
    return auth_system in AUTH_SYSTEMS and hasattr(AUTH_SYSTEMS[auth_system], 'check_constraint')

def can_list_categories(auth_system):
    return auth_system in AUTH_SYSTEMS and hasattr(AUTH_SYSTEMS[auth_system], 'list_categories')