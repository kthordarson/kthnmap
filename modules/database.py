from os import getenv
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
from .nmap import NmapSession

mysql_cmds = {
'scans' : """
					create table if not exists scans
					(
						scanid int primary key not null auto_increment,
						xmlfilename  varchar(255),
						scandate varchar(255),
						scanstart_str varchar(255),
						sessionname varchar(255),
						hostcount int,
						servicecount int
					);
 """,
'sessions' : """
					create table if not exists sessions
					(
						sessionid int primary key not null auto_increment,
						sessionname varchar(255),
						scanid int,
						key scans_fk (scanid),
						foreign key(scanid) references scans(scanid)

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
						key hosts_fk (hostid),
						foreign key(scanid) references scans(scanid),
						foreign key(hostid) references hosts(hostid)
					);
 """,
  'services' : """
					create table if not exists services
					(
						serviceid int primary key not null auto_increment,
						portnumber int,
						scanid int,
						hostid int,
						key scans_fk (scanid),
						key hosts_fk (hostid),
						foreign key(scanid) references scans(scanid),
						foreign key(hostid) references hosts(hostid)
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

def check_existing_xml(session, xmlfile):
	sql = f"select * from scans where xmlfilename = '{xmlfile}'"
	res = session.execute(sql).fetchall()
	if len(res) == 0:
		return False
	else:
		return True

def get_engine():
	dbuser = getenv('nmapdbuser')
	dbpass = getenv('nmapdbpass')
	dbhost = getenv('nmapdbhost')
	dbname = getenv('nmapdbname')
	dburl = f"mysql+pymysql://{dbuser}:{dbpass}@{dbhost}/{dbname}?charset=utf8mb4"
	return create_engine(dburl)

def to_database(scan=None, xmlfile=None, drop=False, check=True, sessionname=None):
	#Session = sessionmaker(bind=engine)
	#session = Session()
	#metadata = MetaData(engine)
	logger.debug(f'[todb] scan: {scan} xmlfile: {xmlfile} drop: {drop} check: {check}')
	engine = get_engine()
	with Session(engine) as session:
		if drop:
			drop_tables(session)
		create_tables(session)
		if check:
			if check_existing_xml(session, xmlfile):
				logger.warning(f'xmlfile {xmlfile} already in database')
				return
		scan.sessionname = sessionname
		session.add(scan)
		session.commit()
		logger.debug(f'Added scan to database {scan.scanid}')
		ns = NmapSession(sessionname=sessionname)
		ns.scanid = scan.scanid
		session.add(ns)
		session.commit()
		logger.debug(f'Added session {ns} to database {ns.sessionid} {ns.scanid}')
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
			#logger.debug(f'Added host to database {host} {host.ports}')
		logger.debug(f'Added {len(hosts)} to database')