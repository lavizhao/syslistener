#!/usr/bin/python3

'''
这个脚本的目的是管理mysql中的表数据
'''
import sys
from .read_conf import config
from .analyzer import log_analyzer

logana = log_analyzer()

#import pymysql as mysql
import mysql.connector

dbcf = config("../../conf/db.conf")

class mydb:
    def __init__(self):
        #设置mysql连接
        passwd = dbcf['passwd'] if dbcf['passwd'] != 'null' else ''
        self.conn = mysql.connector.connect(host=dbcf["host"],user=dbcf['user'],passwd=passwd ,port=dbcf['port'])

    def create_db(self):
        cur = self.conn.cursor()
        cur.execute("CREATE DATABASE IF NOT EXISTS syslistener DEFAULT CHARSET utf8")
        self.conn.commit()

    def drop_db(self):
        cur = self.conn.cursor()
        cur.execute("drop database if exists syslistener;")
        self.conn.commit()

    #三个sql,建表
    def create_tbls(self):    
        sql1 = 'create table syslogd_tbl(indx int PRIMARY KEY  AUTO_INCREMENT,severity int,time datetime,node_id varchar(200),device_id varchar(200),description varchar(30000),orign varchar(4000),router_ip varchar(200),router_port varchar(200))'
        sql2 = 'create table superfw_tbl(indx int PRIMARY KEY  AUTO_INCREMENT,severity int,time datetime,node_id varchar(200),device_id varchar(200),usr_name varchar(200),system_device_id varchar(200),permission varchar(200),login_type varchar(200), login_ip varchar(200), operate_content varchar(1000),orign varchar(4000),router_ip varchar(200),router_port varchar(200))'
        sql3 = 'create table viruslog_tbl(indx int PRIMARY KEY  AUTO_INCREMENT,severity int, time datetime,node_id varchar(200), device_id varchar(200), virus_name varchar(300), threat_type varchar(200), danger_type varchar(200), spread_virus_device_name varchar(200), spread_virus_device_ip varchar(200), spread_virus_device_port varchar(200), get_virus_device_name varchar(200), get_virus_device_ip varchar(200), get_virus_device_port varchar(200), get_virus_device_protocol varchar(200), virus_size int,virus_info varchar(3000),orign varchar(4000),router_ip varchar(200),router_port varchar(200))'

        cur = self.conn.cursor()
        cur.execute('use syslistener;')

        cur.execute(sql1)
        cur.execute(sql2)
        cur.execute(sql3)
    
        self.conn.commit()
        
    def drop_tbls(self):
        sql1 = 'drop table syslogd_tbl'
        sql2 = 'drop table superfw_tbl'
        sql3 = 'drop table viruslog_tbl'
        
        cur = self.conn.cursor()
        cur.execute('use syslistener;')

        cur.execute(sql1)
        cur.execute(sql2)
        cur.execute(sql3)

        self.conn.commit()

    def insert_tbls(self,log,ip,port):
        sql_string = logana.get_insert_string(log,ip,port)

        cur = self.conn.cursor()
        cur.execute('use syslistener;')

        cur.execute(sql_string)
        self.conn.commit()        
