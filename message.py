'''
    id = Column('id', INTEGER(),
                primary_key=True, nullable=False, doc='increment id')
    Account manage module
'''
# from tornado.web import HTTPError
# import datetime
# import math

# from MySQLdb import (IntegrityError)

from db import db
# import util

def get_message(_id):
    return db.get_message(_id)

def get_messages(groups, mask, isimg, gmtype, label, pos, nums):
    '''
        get messages 
        filter  : groups, mask
        position: start , per
    '''
    return db.get_messages(groups, mask, isimg, gmtype, label, pos, nums)

def get_messages2(groups, mask, isimg, gmtype, label, pos, nums):
    '''
        current only support jobs messages
    '''
    assert mask is 16
    return db.get_messages2(groups, mask, isimg, gmtype, label, pos, nums)
