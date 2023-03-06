from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime, Date, Boolean, ForeignKey, text, update
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy import Engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session)
from IPy import IP
from datetime import datetime
import os
import copy
import ipaddress
from loguru import logger
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from modules.constants import PROTOCOLS, PORT_OPT_COMBINED, PORT_OPT_TCP, PORT_OPT_UDP
#from modules import constants
#from modules import helpers

def db_init(engine: Engine) -> None:
	Base.metadata.create_all(bind=engine)

class Base(DeclarativeBase):
	pass


def sort_xml_list(xml_list):
	newlist=[]
	for xmlfile in xml_list:
		try:
			nmap_xml = ET.parse(xmlfile)
		except ET.ParseError as e:
			logger.error(f'Error parsing {xmlfile} {e}')
			continue
		root = nmap_xml.getroot()
		scandate = datetime.fromtimestamp(int(root.attrib['start']))
		newlist.append({'filename':xmlfile, 'scandate':scandate})
	newlist.sort(key=lambda x: x['scandate'])
	return newlist

def sortIpList(ip_list):
	ipl = [(IP(ip).int(), ip) for ip in ip_list]
	ipl.sort()
	return [ip[1] for ip in ipl]




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
		return f'nmapscan date={self.scanstart_str} hosts={len(self.Hosts)} services={len(self.Services)} sc={self.servicecount} ac={self.alivecount} hc={self.hostcount}'

	def parseNmapXmlFile(self, nmapXmlFilename):
		count = 0
		# Loop through all nmap xml files
		iMaxStatusLen = 0
		count += 1
		# Try to parse xml and record any failures
		nmap_xml = ""
		try:
			nmap_xml = ET.parse(nmapXmlFilename)
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
						try:
							Servicename = xPort.find('.//service').get('name', 'na')
						except AttributeError:
							Servicename = 'na'
						try:
							product = xPort.find('.//service').get('product', 'na')
						except AttributeError:
							product = 'na'
						try:
							extra = xPort.find('.//service').get('extrainfo', 'na')
						except AttributeError:
							extra = 'na'
						try:
							version = xPort.find('.//service').get('version', 'na')
						except AttributeError:
							version = 'na'
						try:
							ostype = xPort.find('.//service').get('ostype', 'na')
						except AttributeError:
							ostype = 'na'
						# logger.debug(f'host={newhost} port={xPort} servicename={Servicename} product={product} extra={extra} version={version} ostype={ostype}')
						if Servicename == 'na':
							pass
							# logger.warning(f'host={newhost} port={xPort} servicename={Servicename} product={product} extra={extra} version={version} ostype={ostype}')
						newhost.addPortService(servicename=Servicename, protocol=Protocol, portnumber=PortNumber, product=product, extra=extra, version=version, ostype=ostype)
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
		hostIps = sortIpList(self.Hosts)
		for ip in hostIps:
			host = copy.deepcopy(self.Hosts[ip])
			if not host.alive:
				continue
			matchedHosts.append(host)
		return matchedHosts

	def getAliveHosts(self, filters=None):
		return [host.ip for host in self.getHosts(filters) if host.alive]

	def getServices(self):
		return self.Services

	def getUniquePortIds(self, protocol=PORT_OPT_COMBINED, hosts=None):
		allPorts = set()
		if(hosts == None):
			hosts = self.getHosts()
		for host in hosts:
			if protocol == PORT_OPT_TCP:
				allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_TCP))
			elif protocol == PORT_OPT_UDP:
				allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_UDP))
			else:
				allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_TCP))
				allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_UDP))
		return sorted(allPorts)

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
		self.ports = []
		self.services = []
		self.servicecount = 0
		self.matched = True # Used for filtering
		# logger.debug(f'host init scan:{self.scanid} {scanid}')

	# def __str__(self):
	#     return f'ip={self.ip} hostname={self.hostname} alive={self.alive} ports={len(self.ports)}'

	# def __repr__(self):
	#     return f'ip={self.ip} hostname={self.hostname} alive={self.alive} ports={len(self.ports)}'
	def __repr__(self):
		return self.ip

	def getHostServices(self):
		return self.services

	def getState(self):
		state = "up"
		if not self.alive:
			state = "down"
		return state

	def addPortService(self, servicename, protocol, portnumber,  product, extra, version, ostype):
		newPort = NmapPort(servicename=servicename, protocol=protocol, portnumber=portnumber,  product=product, extra=extra, version=version, ostype=ostype)
		self.ports.append(newPort)
		self.servicecount += 1
		#newservice = NmapService(servicename=servicename, protocol=protocol, portnumber=portnumber, product=product, extra=extra, version=version, ostype=ostype)
		#self.services.append(newservice)
		#return newPort

	def getUniquePortIds(self,protocol='',port_filter=[], service_filter=[]):
		allPortIds = []
		for port in self.ports:
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
		return f'proto={self.protocol} portnumber={self.portnumber} service={self.service} prod={self.product} extra={self.extra} version={self.version} ostype={self.ostype}'

	def __repr__(self) -> str:
		return f'proto={self.protocol} portnumber={self.portnumber} service={self.service} prod={self.product} extra={self.extra} version={self.version} ostype={self.ostype}'




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

def check_existing_xml(session, xmlfile):
	#sql = text(f"select * from scans where xmlfilename = '{xmlfile}'")
	res = session.query(NmapScan).filter(NmapScan.xmlfilename == xmlfile).all()
	if len(res) == 0:
		return False
	else:
		return True


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
		return create_engine('sqlite:///nmapscans.db', echo=False, connect_args={'check_same_thread': False})
	else:
		raise TypeError(f'[db] unknown dbtype {dbtype} ')

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

def xmlscan_to_database(scan=None, xmlfile=None, check=True, session=None):
	logger.debug(f'[todb] scan: {scan}')
	if check_existing_xml(session, xmlfile):
		logger.warning(f'xmlfile {xmlfile} already in database')
		return
	else:
		session.add(scan)
		session.commit()
		# hosts = scan.getHosts()
		hostcount = 0
		errcount = 0
		hostupdatecount = 0
		portupdatecount = 0
		noportcount = 0
		newportcount = 0
		for host in scan.getHosts():
			host.scanid = scan.scanid
			if len(host.ports) == 0:
				noportcount += 1
				#host.openports = 0
				#host.ports = 0
				#host.services = 0
			# else:
			portlist = str([f'{k.portnumber}' for k in host.ports]).replace('[','').replace(']','')
			host.openports = len(portlist.split(','))
			#host.openports = len(host.ports)
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
		# logger.debug(f'Added {hostcount} of {len(scan.getHosts())} to database errors:{errcount} noport:{noportcount} newports:{newportcount} hostupdates:{hostupdatecount} portupdates:{portupdatecount}')