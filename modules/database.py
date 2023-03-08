import os
import re
from inspect import isclass
from dataclasses import dataclass, fields, field, is_dataclass
from sqlalchemy import create_engine, MetaData, Column, Integer, update, text
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime, Date, Boolean, ForeignKey
from sqlalchemy import Engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session)

import sqlalchemy
from loguru import logger
import datetime


class Base(DeclarativeBase):
	pass



def get_engine(dbtype: str) -> Engine:
	dbuser = os.getenv('nmapdbuser')
	dbpass = os.getenv('nmapdbpass')
	dbhost = os.getenv('nmapdbhost')
	dbname = os.getenv('nmapdbname')
	if dbtype == 'mysql':
		if not dbuser or not dbpass or not dbhost or not dbname:
			raise AttributeError(f'[db] missing db env variables')
		dburl = f"mysql+pymysql://{dbuser}:{dbpass}@{dbhost}/{dbname}?charset=utf8mb4"
		return create_engine(dburl)
	# return create_engine(dburl, pool_size=200, max_overflow=0)
	elif dbtype == 'postgresql':
		if not dbuser or not dbpass or not dbhost or not dbname:
			raise AttributeError(f'[db] missing db env variables')
		dburl = f"postgresql://{dbuser}:{dbpass}@{dbhost}/{dbname}"
		return create_engine(dburl)
	elif dbtype == 'sqlite':
		return create_engine('sqlite:///localscan.db', echo=False, connect_args={'check_same_thread': False})
	else:
		raise TypeError(f'[db] unknown dbtype {dbtype} ')


mysql_cmds = {
'scans' : text("""
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
 """),
 'hosts' : text("""
					create table if not exists hosts
					(
						hostid int primary key not null auto_increment,
						scanid int,
						ip  varchar(255),
						hostname varchar(255),
						openports int,
						portlist varchar(512),
						servicelist varchar(512),
						alive bool,
						firstseen varchar(255),
						lastseen varchar(255),
						key scans_fk (scanid),
						foreign key(scanid) references scans(scanid)
					);
 """),
 'ports' : text("""
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
 """)}
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






class NmapScan(Base):
	__tablename__ = 'scans'
	scanid = Column(Integer, primary_key=True)
	#Hosts:str = {}
	#Services:str = []
	scandate = Column(String(255))
	scanstart_str = Column(String(255))
	xmlfilename = Column(String(255))
	hostcount = Column(Integer)
	alivecount = Column(Integer)
	servicecount = Column(Integer)
	#Hosts = Column(String(255))
	#Services = Column(String(255))
	scanargs = Column(String(1024))
	def __init__(self, xmlFile=None):
		# Import xml files
		self.Hosts = {}
		self.Services = []
		self.hostcount = 0
		self.alivecount = 0
		self.servicecount = 0
		self.xmlfilename = xmlFile
		if xmlFile:
			self.parseNmapXmlFile(xmlFile)


	def __repr__(self):
		return f'nmapscan date={self.scanstart_str} sc={self.servicecount} ac={self.alivecount} hc={self.hostcount}' # hosts={len(self.Hosts)} services={len(self.Services)}

	def parseNmapXmlFile(self, nmapXmlFilename):
		count = 0
		# Loop through all nmap xml files
		iMaxStatusLen = 0
		count += 1
		# Try to parse xml and record any failures
		nmap_xml = ""
		try:
			nmap_xml = None #ET.parse(nmapXmlFilename)
		except Exception as e:
			logger.error(f'{e} failed to import {nmapXmlFilename}')
			return
		# Record that file successfully loaded
		# Find all hosts within xml file
		root = nmap_xml.getroot()
		self.scandate = root.attrib['start']
		self.scanstart_str = root.attrib['startstr']
		self.scanargs = root.attrib['args']
		for xHost in nmap_xml.findall('.//host'):
			ip = xHost.find("address[@addrtype='ipv4']").get('addr')
			if ip not in self.Hosts:
				try:
					hostname = xHost.find('.//hostname').get('name') # hostname will be in nmap xml if PTR (reverse lookup) record present
				except:
					hostname = ip
				alive = (xHost.find("status").get('state') == 'up')
				newhost = NmapHost(ipaddress=ip, hostname=hostname, scanid=self.scanid, alive=alive)
				for xPort in xHost.findall('.//port'):

					# Only parse open ports
					if xPort.find('.//state').get('state') == 'open':
						self.servicecount += 1
						PortNumber = int(xPort.get('portid'))
						Protocol = xPort.get('protocol')

						#curService, product, extra, version, ostype = '', '', '', '',''
	#                    if(None != xPort.find('.//service')):
						#if xPort.find('.//service'):
						Servicename = xPort.find('.//service').get('name', 'na')
						product = xPort.find('.//service').get('product', 'na')
						extra = xPort.find('.//service').get('extrainfo', 'na')
						version = xPort.find('.//service').get('version', 'na')
						ostype = xPort.find('.//service').get('ostype', 'na')
						newPort = NmapPort(servicename=Servicename, protocol=Protocol, portnumber=PortNumber,  product=product, extra=extra, version=version, ostype=ostype)
						newhost.portlist.append(newPort)
						print(f'newhost={newhost} xport {xPort} pn={PortNumber} p={Protocol} np={newPort} nhpl={len(newhost.portlist)}')
						#newhost.addPortService(servicename=Servicename, protocol=Protocol, portnumber=PortNumber, product=product, extra=extra, version=version, ostype=ostype)
						#self.addService(curService, ip, curPortId, product, extra, version, ostype)
				self.Hosts[ip] = newhost
				self.hostcount += 1
				if newhost.servicecount >= 1:
					self.alivecount += 1

	# Ger or create new service with host/ip/port details
	def addService(self, svcName, ip, port, product, extra, version, ostype):
		curService = self.getService(svcName, product, extra, version, ostype)
		curServiceHost = self.getServiceHost(curService, ip)
		if port not in curServiceHost.ports:
			curServiceHost.ports.append(port)
		if port not in curService.ports:
			curService.ports.append(port)

	# Get service host or create if necessary
	def getServiceHost(self, service, ip):
		for host in service.hosts:
			if host.ip == ip:
				return host

		newServiceHost = NmapHost(ip, self.scanid)
		service.hosts.append(newServiceHost)
		return newServiceHost

	# Get service or create if necessary
	def getService(self, svcName, product, extra, version, ostype):
		for service in self.Services:
			if service.name == svcName:
				return service #.name, service.product, service.extra, service.version, service.ostype

		#newService = NmapService(name=svcName)
		newService = NmapService(servicename=svcName, product=product,extra=extra, version=version, ostype=ostype)
		#newService.product = product
		#newService.extra = extra
		#newService.version = version
		#newService.ostype = ostype
		self.Services.append(newService)
		# logger.debug(f'[getservice] new service: {newService} total services: {len(self.Services)}')
		return newService

	def getHostDictionary(self, filters=None):
		hostDict = {}
		for host in self.getHosts(filters):
			hostDict[host.ip] = host
		return hostDict

	def getHosts(self):
		matchedHosts = []
		hostIps = self.Hosts # sortIpList(self.Hosts)
		for ip in hostIps:
			host = ip # copy.deepcopy(self.Hosts[ip])
			if not host.alive:
				continue
			matchedHosts.append(host)
		return matchedHosts

	def getAliveHosts(self, filters=None):
		return [host.ip for host in self.getHosts(filters) if host.alive]

	def getServices(self):
		return self.Services

class NmapService(Base):
	__tablename__ = 'services'
	serviceid = Column(Integer, primary_key=True)
	name = Column(String(255))
	product = Column(String(255))
	extra = Column(String(255))
	version = Column(String(255))
	ostype = Column(String(255))
	scanid = Column(Integer, ForeignKey('scans.scanid'))
	hostid = Column(Integer, ForeignKey('hosts.hostid'))
	def __init__(self,protocol=None, portnumber=None, servicename=None, product=None, extra=None, version=None, ostype=None):#, name, product, extra, version, ostype):
		self.protocol = protocol
		self.product = product
		self.extra = extra
		self.version = version
		self.ostype = ostype
		self.portnumber = portnumber
		self.servicename = servicename
		#self.hosts = []
		#self.ports = []

	# def __str__(self):
	#     return f'name={self.name} prod={self.product} extra={self.extra} version={self.version} os={self.ostype}'

	def __repr__(self):
		return f'name={self.name} prod={self.product} extra={self.extra} version={self.version} os={self.ostype}'


class NmapHost(Base):
	__tablename__ = 'hosts'
	hostid = Column(Integer, primary_key=True)
	ip = Column(String(255))
	hostname = Column(String(255))
	alive:bool = Column(Boolean)
	firstseen = Column(String(255))
	lastseen = Column(String(255))
	scanid = Column(Integer, ForeignKey('scans.scanid'))
	openports = Column(Integer)
	portlist = Column(String(512))
	servicelist = Column(String(255))
	def __init__(self, ipaddress=None, hostname=None, scanid=None, alive=None) :
		self.scanid = scanid
		self.ip = ipaddress
		self.hostname = hostname
		self.alive = alive
		self.portlist = []
		self.services = []
		self.servicecount = 0
		self.matched = True # Used for filtering
		# logger.debug(f'host init scan:{self.scanid} {scanid}')

	# def __str__(self):
	#     return f'ip={self.ip} hostname={self.hostname} alive={self.alive}'

	# def __repr__(self):
	#     return f'ip={self.ip} hostname={self.hostname} alive={self.alive}'
	def __repr__(self):
		return f'Host: ip={self.ip}'

	def getHostServices(self):
		return self.services

	def getState(self):
		state = "up"
		if not self.alive:
			state = "down"
		return state

	def getUniquePortIds(self,protocol='',port_filter=[], service_filter=[]):
		allPortIds = []
		for port in self.portlist:
			if(len(port_filter) > 0 and port.portnumber not in port_filter):
				continue
			if(len(service_filter) > 0 and port.service not in service_filter):
				continue
			if len(protocol) == 0 or port.protocol == protocol:
				allPortIds.append(port.portnumber)
		uniquePortIds = set(allPortIds)
		return sorted(uniquePortIds)

	def getHostname(self):
		if self.hostname == self.ip:
			return ''
		return self.hostname

class NmapPort(Base):
	__tablename__ = 'ports'
	portid = Column(Integer, primary_key=True)
	portnumber = Column(Integer)
	protocol = Column(String(255))
	servicename = Column(String(255))
	product = Column(String(255))
	extra = Column(String(255))
	version = Column(String(255))
	ostype = Column(String(255))
	firstseen = Column(String(255))
	lastseen = Column(String(255))
	scanid = Column(Integer, ForeignKey('scans.scanid'))
	hostid = Column(Integer, ForeignKey('hosts.hostid'))
	def __init__(self, protocol=None, portnumber=None, servicename=None, product=None, extra=None, version=None, ostype=None):
		self.protocol = protocol
		self.portnumber = portnumber
		self.servicename = servicename
		self.product = product
		self.extra = extra
		self.version = version
		self.ostype = ostype
		self.matched = True # Used for filtering

	def __str__(self) -> str:
		return f'proto={self.protocol} portnumber={self.portnumber} service={self.servicename} prod={self.product} extra={self.extra} version={self.version} ostype={self.ostype}'

	def __repr__(self) -> str:
		return f'proto={self.protocol} portnumber={self.portnumber} service={self.servicename} prod={self.product} extra={self.extra} version={self.version} ostype={self.ostype}'


def drop_tables(engine):
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
	pass
	# for table in mysql_cmds:
	# 	session.execute(mysql_cmds[table])
	# 	session.commit()
		# logger.debug(f'create {table}')
	# logger.debug(f'create done')
#	session.execute('create table if not exists scans (id int primary key not null auto_increment);')
	#session.commit()


