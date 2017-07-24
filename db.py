#!/usr/bin/env python
#coding=utf-8
# from DBUtils.PooledDB import PooledDB
from DBUtils.PersistentDB import PersistentDB
# from beaker.cache import CacheManager
# import functools
# import settings
try:
    import MySQLdb
except:
    pass

import settings
# import util

__cache_timeout__ = 600

# 0b 01111111 11111111 11111111 11111111
__MASK__ = 2147483647

# cache = CacheManager(cache_regions= {'short_term':{'type':'memory', 
#                                                    'expire':__cache_timeout__}})

ticket_fds = [
    'user', 'acct_input_octets', 'acct_output_octets', 'acct_input_packets', 'acct_output_packets', 
    'acct_session_id', 'acct_session_time', 'acct_start_time', 'acct_stop_time', 
    'acct_terminate_cause', 'frame_netmask', 'framed_ipaddr', 'is_deduct', 'nas_addr',
    'session_timeout', 'start_source', 'stop_source', 'mac_addr'
]

class Connect:
    def __init__(self, dbpool):
        self.conn = dbpool.connect()

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.conn.close()

class Cursor:
    def __init__(self, dbpool):
        self.conn = dbpool.connect()
        self.cursor = dbpool.cursor(self.conn)

    def __enter__(self):
        return self.cursor

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.conn.close()

class MySQLPool():
    def __init__(self, config):
        self.dbpool = PersistentDB(
            creator=MySQLdb,
            db=config['db'],
            host=config['host'],
            port=config['port'],
            user=config['user'],
            passwd=config['passwd'],
            charset=config['charset'],
            maxusage=config['maxusage'],

            # read & write timeout
            read_timeout=30,
            write_timeout=30,
        )

    def cursor(self, conn):
        return conn.cursor(MySQLdb.cursors.DictCursor)

    def connect(self):
        return self.dbpool.connection()

pool_class = {'mysql':MySQLPool}

class Store():
    def setup(self, config):
        self.dbpool = MySQLPool(config['database'])

    def _combine_query_kwargs(self, **kwargs):
        '''
            convert query kwargs to str
        '''
        query_list = []
        for key,value in kwargs.iteritems():
            if isinstance(value, int):
                query_list.append('{}={}'.format(key, value))
            else:
                query_list.append('{}="{}"'.format(key, value))
        return 'and '.join(query_list)

    def add_project(self, **kwargs):
        '''
            insert new project
        '''
        with Connect(self.dbpool) as conn:
            cur = conn.cursor(MySQLdb.cursors.DictCursor)
            key_str = ', '.join(kwargs.keys())
            value_str = ', '.join(["'{}'".format(item) for item in kwargs.values()])
            sql = 'insert into project ({}) values({})'.format(key_str, value_str)
            cur.execute(sql)
            conn.commit()

    def get_message(self, _id):
        '''
            get special message
        '''
        with Cursor(self.dbpool) as cur:
            sql = '''select message.* from message
            where message.id="{}"'''.format(_id)
            cur.execute(sql)
            return cur.fetchone()

    def get_messages(self, groups, mask, isimg, gmtype, label, pos, nums=10):
        '''
            id title subtitle section mask author groups status ctime content image
            get groups's messages excelpt content filed
            order by ctime desc 
            groups : message's group
            mask : message type (combine by bit operator)
            pos : where to get special messages
            isimg : search messages which image <> '';
        '''
        with Cursor(self.dbpool) as cur:
            filters = 'message.id, message.title, message.subtitle, message.mask, message.author, message.groups, message.status, message.ctime, message.image'
            sql = ''
            gmtype = 'message.gmtype = {} and '.format(gmtype) if gmtype else ''
            isimg = 'message.image <> "" and '.format(isimg) if isimg else ''
            label = " and label like'%{}%'".format(label) if label else ''

            if mask:
                sql = '''select {} from message
                where {}{}message.groups = {} and message.mask & {} = {} and 
                order by message.status desc, message.ctime desc limit {},{}
                '''.format(filters, gmtype, isimg, groups, __MASK__, mask, pos, nums)
            else:
                # doesn't check message type
                sql = '''select {} from message 
                where {}{}message.groups = {} {} 
                order by message.status desc, message.ctime desc limit {},{}
                '''.format(filters, gmtype, isimg, groups, label, pos, nums)

            cur.execute(sql)
            results = cur.fetchall()
            return results if results else []

    def get_messages2(self, groups, mask, isimg, gmtype, label, pos, nums=10):
        '''
        '''
        with Cursor(self.dbpool) as cur:
            # filters = 'message.id, message.title, message.subtitle, message.mask, message.author, message.groups, message.status, message.ctime, message.image'
            sql = ''
            # gmtype = 'message.gmtype = {} and '.format(gmtype) if gmtype else ''
            # isimg = 'message.image <> "" and '.format(isimg) if isimg else ''
            # label = " and label like'%{}%'".format(label) if label else ''

            sql = '''select message.* from message 
            where message.groups = {} and message.mask & {} = {} and 
            order by message.status desc, message.ctime desc limit {},{}
            '''.format(groups, __MASK__, mask, pos, nums)

            cur.execute(sql)
            results = cur.fetchall()
            return results if results else []


db = Store()
db.setup(settings)
