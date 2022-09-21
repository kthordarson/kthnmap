import re
from inspect import isclass
from dataclasses import dataclass, fields, field, is_dataclass
from sqlalchemy import create_engine, MetaData, Column, Integer
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import sqlalchemy
from loguru import logger
import datetime

mysql_cmds = {
'scans' : """
					create table if not exists scans
					(
						scanid int primary key not null auto_increment,
						xmlfilename  varchar(255),
						scandate varchar(255),
						scanstart_str varchar(255)
					);
 """,
 'hosts' : """
					create table if not exists hosts
					(
						hostid int primary key not null auto_increment,
						scanid int,
						ip  varchar(255),
						hostname varchar(255),
						openports int,
						ports varchar(255),
						services varchar(255),
						alive bool,
						key scans_fk (scanid),
						foreign key(scanid) references scans(scanid)
					);
 """,
 'ports' : """
					create table if not exists ports
					(
						portid int primary key not null auto_increment,
						portnumber int,
						scanid int,
						hostid int,
						key scans_fk (scanid),
						foreign key(scanid) references scans(scanid)
					);
 """,
  'services' : """
					create table if not exists services
					(
						serviceid int primary key not null auto_increment,
						portnumber int,
						scanid int,
						hostid int
					);
 """
}


def drop_tables(session):
	session.execute('SET FOREIGN_KEY_CHECKS=0;')
	session.commit()
	for table in mysql_cmds:
		session.execute(f'drop table if exists {table} CASCADE;')
		session.commit()
		logger.debug(f'dropped {table}')
	session.execute('SET FOREIGN_KEY_CHECKS=1;')
	session.commit()

def create_tables(session):
	for table in mysql_cmds:
		session.execute(mysql_cmds[table])
		session.commit()
		logger.debug(f'create {table}')
	logger.debug(f'create done')
#	session.execute('create table if not exists scans (id int primary key not null auto_increment);')
	#session.commit()

def to_database(scan):
	dbuser = 'nmapscan'
	dbpass = 'nmapscan'
	dbhost = 'elitedesk'
	dbname = 'nmapscans'
	dburl = f"mysql+pymysql://{dbuser}:{dbpass}@{dbhost}/{dbname}?charset=utf8mb4"
	engine = create_engine(dburl)
	#Session = sessionmaker(bind=engine)
	#session = Session()
	#metadata = MetaData(engine)
	with Session(engine) as session:
		#drop_tables(session)
		create_tables(session)
		session.add(scan)
		session.commit()
		logger.debug(f'Added scan to database {scan.scanid}')
		hosts = scan.getHosts()
		for host in hosts:
			host.scanid = scan.scanid
			host.openports = len(host.ports)
			ports = str([k.portnumber for k in host.ports]).replace('[','').replace(']','')
			host.ports = ports # str([k.portnumber for k in host.ports])
			services = str([k for k in host.services]).replace('[','').replace(']','')
			host.services = services
			session.add(host)
			session.commit()
			logger.debug(f'Added host to database {host} {host.ports}')
		logger.debug(f'Added {len(hosts)} to database')