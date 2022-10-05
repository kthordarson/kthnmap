from os import getenv
import re
from inspect import isclass
from dataclasses import dataclass, fields, field, is_dataclass
from sqlalchemy import create_engine, MetaData, Column, Integer, update
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import sqlalchemy
from loguru import logger
import datetime
from .nmap import NmapHost, NmapPort, NmapScan, NmapService

mysql_cmds = {
'scans' : """
					create table if not exists scans
					(
						scanid int primary key not null auto_increment,
						xmlfilename  varchar(255),
						scandate varchar(255),
						scanstart_str varchar(255),
						scanargs varchar(2024),
						hostcount int,
						alivecount int,
						servicecount int
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
						portlist varchar(255),
						servicelist varchar(512),
						alive bool,
						firstseen varchar(255),
						lastseen varchar(255),
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
						protocol varchar(255),
						servicename varchar(255),
						product varchar(255),
						extra varchar(255),
						version varchar(255),
						ostype varchar(255),
						firstseen varchar(255),
						lastseen varchar(255),
						key scans_fk (scanid),
						key hosts_fk (hostid),
						foreign key(scanid) references scans(scanid),
						foreign key(hostid) references hosts(hostid)
					);
 """}
#  ,
#   'services' : """
# 					create table if not exists services
# 					(
# 						serviceid int primary key not null auto_increment,
# 						name varchar(255),
# 						product varchar(255),
# 						extra varchar(255),
# 						version varchar(255),
# 						ostype varchar(255),
# 						portnumber int,
# 						scanid int,
# 						hostid int,
# 						key scans_fk (scanid),
# 						key hosts_fk (hostid),
# 						foreign key(scanid) references scans(scanid),
# 						foreign key(hostid) references hosts(hostid)
# 					);
#  """
# }


def drop_tables():
	engine = get_engine()
	session = Session(engine)
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
		# logger.debug(f'create {table}')
	# logger.debug(f'create done')
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

def get_hostid(session, ipaddress):
	sql = f"select hostid from hosts where ip = '{ipaddress}'"
	res = []
	try:
		res = session.execute(sql).fetchone()[0]
	except:
		pass
	if res is None:
		return []
	return res

def get_host(session, ipaddress):
	sql = f"select * from hosts where ip = '{ipaddress}'"
	res = []
	try:
		res = session.execute(sql).fetchone()
	except:
		return []
	if res is None:
		return []
	return res

def get_servicelist(session=None, hostid=None):
	sql = f"select servicelist from hosts where hostid = '{hostid}'"
	res = []
	try:
		res = session.execute(sql).fetchone()[0]
	except:
		return []
	if res is None:
		return []
	else:
		return res

def get_portlist(session=None, hostid=None):
	sql = f"select portlist from hosts where hostid = '{hostid}'"
	res = []
	try:
		res = session.execute(sql).fetchone()[0]
	except:
		return []
	if res is None:
		return []
	else:
		return res

def get_hostport(session=None, hostid=None, portnumber=None):
	sql = f"select * from ports where portnumber = '{portnumber}' and hostid = '{hostid}'"
	res = []
	try:
		res = session.execute(sql).fetchone()
	except:
		return []
	if res is None:
		return []
	else:
		return res

def get_sessionid(session, sessionname):
	sql = f"select sessionid from sessions where sessionname = '{sessionname}'"
	try:
		res = session.execute(sql).fetchone()[0]
	except:
		return []
	if res is None:
		return []
	return res

def mergeportlist(portlist, oldportlist):
	return set(portlist + oldportlist)

def scan_to_database(results=None, sessionname=None):
	for res in results:
		logger.info(f'[todb] {res}')

def xmlscan_to_database(scan=None, xmlfile=None, check=True):
	#Session = sessionmaker(bind=engine)
	#session = Session()
	#metadata = MetaData(engine)
	logger.debug(f'[todb] scan: {scan}')
	engine = get_engine()
	with Session(engine) as session:
		create_tables(session)
		if check:
			if check_existing_xml(session, xmlfile):
				logger.warning(f'xmlfile {xmlfile} already in database')
				return
		session.add(scan)
		session.commit()
		hosts = scan.getHosts()
		hostcount = 0
		errcount = 0
		hostupdatecount = 0
		portupdatecount = 0
		noportcount = 0
		newportcount = 0
		for host in hosts:
			host.scanid = scan.scanid
			if len(host.ports) == 0:
				noportcount += 1
				#host.openports = 0
				#host.ports = 0
				#host.services = 0
			else:
				host.openports = len(host.ports)
				portlist = str([f'{k.servicename} {k.portnumber}' for k in host.ports]).replace('[','').replace(']','')
				# servicelist = str([k for k in host.services]).replace('[','').replace(']','')
				servicelist = str([f'{k.name} {k.portnumber}' for k in host.services]).replace('[','').replace(']','')
				host.portlist = portlist
				host.servicelist = servicelist
				hcheck = len(get_host(session, host.ip))
				if hcheck == 0:
					host.firstseen = scan.scandate
					host.lastseen = scan.scandate
					session.add(host)
					try:
						session.commit()
						hostid = get_hostid(session, host.ip)
						hostcount += 1
					except (ProgrammingError, OperationalError, DataError) as e:
						logger.error(f'[todb] err:{e} host:{host}')
						session.rollback()
						errcount += 1
				else:
					# logger.debug(f'updatehost {host}')
					hostid = get_hostid(session, host.ip)
					#hostid = get_hostid(session, host.ip)
					host.lastseen = scan.scandate
					oldportlist = get_portlist(session, hostid)
					oldservicelist = get_servicelist(session, hostid)
					if len(portlist)-len(oldportlist) < 0:
						ptemp = [k for k in portlist.split(',')]
						otemp = [k for k in oldportlist.split(',')]
						newportlist = ','.join(set([*ptemp, *otemp]))
						#newportlist = set([k for k in portlist.split(',')]+[m for m in oldportlist.split(',')])
						#logger.info(f'\tplist={portlist}')
						#logger.info(f'\told={oldportlist}')
						#logger.info(f'\tnew={newportlist}')						
						logger.warning(f'host={host} pdiff={len(portlist)-len(oldportlist)} p={len(portlist)} o={len(oldportlist)} n={len(newportlist)}')
						portlist = newportlist
					if len(servicelist)-len(oldservicelist) < 0:
						logger.warning(f'sdiff={len(servicelist)-len(oldservicelist)} s={len(servicelist)} o={len(oldservicelist)}')
						logger.info(f'\tslist={servicelist}')
						logger.info(f'\told={oldservicelist}')
					stmt = update(NmapHost).where(NmapHost.hostid == hostid).values(lastseen=host.lastseen, portlist=portlist, servicelist=servicelist)
					session.execute(stmt)
					hostupdatecount += 1
					#session.query(NmapHost).filter(NmapHost.hostid == hostid).update({"lastseen": scan.scandate})


				ports = [k for k in host.ports]
				for p in ports:
					portcheck = get_hostport(session=session, portnumber=p.portnumber, hostid=hostid)
					if len(portcheck) == 0:
						p.scanid = host.scanid
						p.hostid = hostid
						p.firstseen = scan.scandate
						p.lastseen = scan.scandate
						session.add(p)
						session.commit()
						newportcount += 1
					else:
						#updateport
						p.lastseen = scan.scandate
						#p.hostid = host.hostid
						if p.product != portcheck.product:
							if portcheck.product in ['na', 'http']:
								logger.warning(f'host={host}  skipping product change {p.product} to {portcheck.product}')
							if p.product == 'na':
								logger.info(f'host={host}  product change {p.product} to {portcheck.product}')
								p.product = portcheck.product
							portupdatecount += 1
							#if portcheck.product == ''
						if p.servicename != portcheck.servicename:
							logger.warning(f'servicename changed {p.servicename} to  {portcheck.servicename}')
							portupdatecount += 1
						if p.extra != portcheck.extra:
							logger.warning(f'extra changed {p.extra} to  {portcheck.extra}')
							portupdatecount += 1
						if p.ostype != portcheck.ostype:
							logger.warning(f'ostype changed {p.ostype} to  {portcheck.ostype}')
							portupdatecount += 1
						if p.version != portcheck.version:
							logger.warning(f'version changed {p.version} to  {portcheck.version}')
							portupdatecount += 1
						stmt = update(NmapPort).where(NmapPort.portnumber == p.portnumber).where(NmapPort.hostid == hostid).values(lastseen=p.lastseen, servicename=p.servicename, product=p.product, extra=p.extra, version=p.version, ostype=p.ostype)
						session.execute(stmt)
						
#			ports = str([k.portnumber for k in host.ports]).replace('[','').replace(']','')
#			host.ports = ports # str([k.portnumber for k in host.ports])
#			services = str([k for k in host.services]).replace('[','').replace(']','')
#			host.services = services
			#logger.debug(f'Added host to database {host} {host.ports}')
		# for service in scan.getServices():
		# 	service.scanid = scan.scanid
		# 	session.add(service)
		# 	session.commit()
		logger.debug(f'Added {hostcount} of {len(hosts)} to database errors:{errcount} noport:{noportcount} newports:{newportcount} hostupdates:{hostupdatecount} portupdates:{portupdatecount}')