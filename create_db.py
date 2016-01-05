#!/usr/bin/env python
#coding:utf-8
'''
    create database's tables
    database : niot
'''
# create project

project_sql = '''
create table if not exists project (
id char(32) not null default '',
name varchar(64) not null default '',
company varchar(32) not null default '',
project varchar(256) not null default '',
mobile varchar(17) not null default '',
ctime date ,
email varchar(48) not null default '',
team varchar(256) not null default '',
city varchar(48) not null default '',
needs varchar(256) not null default '',
plan varchar(128) not null default '',
subtime datetime not null default current_timestamp,
primary key (id));
'''
# unique index idx_project_item(name, mobile))
