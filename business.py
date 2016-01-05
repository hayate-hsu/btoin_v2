'''
    home page business operator
'''
from db import db

PROJECT_FIELDS = set([
    'id', 'name', 'company', 'project', 'mobile', 'ctime', 
    'email', 'team', 'city', 'needs', 'plan', 'subtime',
])

def add_project(**kwargs):
    for key in kwargs.copy():
        if key not in PROJECT_FIELDS:
            del kwargs[key]

    db.add_project(**kwargs) 
