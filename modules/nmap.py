from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime, Date, Boolean, ForeignKey, text, update
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy import Engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session)
from IPy import IP
from datetime import datetime
import os
from loguru import logger
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
from bs4 import BeautifulSoup
from libnmap.parser import NmapParser, NmapReport, NmapHost, NmapService

class Base(DeclarativeBase):
	pass

def db_init(engine: Engine) -> None:
	Base.metadata.create_all(bind=engine)

class XMLFile(Base):
	__tablename__ = 'xmlfiles'
	file_id = Column(Integer, primary_key=True)
	xml_filename = Column(String(255))
	scandate = Column(String(255))
	scanner = Column(String(255))
	scanstart_str = Column(String(255))
	scanargs = Column(String(255))
	valid = Boolean
	read_count = Column(Integer)

	def __init__(self, filename:str):
		self.xml_filename = filename
		self.valid = False
		self.xmldata = None
		self.root = None
		self.hostlist = []
		self.read_count = 0
		self.scandate = None
		self.scanner = None
		self.scanstart_str = None
		self.scanargs = None
		self.et_xml_parse()

	def __repr__(self):
		return f'<XMLFile id:{self.file_id} xml_filename:{self.xml_filename} scanner:{self.scanner} sd:{self.scandate}> '
	
	def et_xml_parse(self):
		try:
			self.xmldata = ET.parse(self.xml_filename)
			self.root = self.xmldata.getroot()
			self.valid = True
		except ParseError as e:
			logger.error(f'[!] Error {e} while parsing self.xml_filename={self.xml_filename}')
			self.valid = False
		except TypeError as e:
			logger.error(f'[!] TypeError {e} while parsing self.xml_filename={self.xml_filename}')
			self.valid = False
		if self.valid:
			self.scanner = self.root.attrib['scanner']
			self.scandate = self.root.attrib['start']
			self.scanstart_str = self.root.attrib['startstr']
			self.scanargs = self.root.attrib['args']
		else:
			self.scanner = 'error'
			self.scandate = 'error'
			self.scanstart_str = 'error'
			self.scanargs = 'error'

			

	def get_libnmap_report(self) -> NmapReport:
		self.read_count += 1
		np = NmapParser()
		report = np.parse_fromfile(self.xml_filename)
		return report

	def get_ports(self):
		# get open ports and services from xlmfile
		# returns a list of dicts with portnumber and service info
		self.read_count += 1
		ports = []
		if self.valid:
			ports_ = self.root.findall('.//port')
			# [{'idx':idx,'tag':k.tag,'attrib':k.attrib}  for idx,k in enumerate(root.findall('./host//*')) if k.tag =='port']
			# [{'idx':idx,'tag':k.tag,'attrib':k.attrib, 'service':[k.attrib for k in k.findall('service')]}  for idx,k in enumerate(root.findall('./host//*')) if k.tag =='port']
		return ports

	def get_hosts_libnmap(self):
		self.read_count += 1
		rep = self.get_libnmap_report()
		hosts_ = [k for k in rep.hosts if k.is_up()]
		hosts = []
		for host in hosts_:
			hosts.append(Host(host.ipv4, host.mac, host.vendor, host.hostnames, rep.started, rep.endtime, self.file_id))
		return hosts

	def get_hosts(self, scanid):
		hosts = []
		if self.valid:
			hosts_ = self.root.findall('.//host')
			if len(hosts_) == 0:
				logger.warning(f'[?] {self} hosts_ empty?')
			for h in hosts_:
				# [(k.tag, k.attrib) for k in host]
				# [k for k in host.iter()]
				# [(k.tag, k.attrib) for k in host.iter()]
				# hostinfo=[{'tag':k.tag, 'attrib':k.attrib} for k in host.iter()]
				starttime = h.get('starttime')
				endtime = h.get('endtime')
				ip_address = h.find("address[@addrtype='ipv4']").get('addr')
				try:
					vendor = h.find("address[@addrtype='mac']").get('vendor')
				except AttributeError as e:
					vendor = 'unknown'
				try:
					macaddr = h.find("address[@addrtype='mac']").get('addr')
				except AttributeError as e:
					macaddr = 'unknown'
				try:
					hostname = h.find('.//hostname').get('name')
				except AttributeError as e:
					hostname = ip_address
				# if h.find("address[@addrtype='mac']"):
				# 	vendor = h.find("address[@addrtype='mac']").get('vendor')
				# 	macaddr = h.find("address[@addrtype='mac']").get('addr')
				# else:
				# 	vendor = 'unknown'
				# 	macaddr = 'unknown'
				# if h.find('.//hostname'):
				# 	hostname = h.find('.//hostname') or 'unknown'
				# else:
				# 	hostname = f'{ip_address}-unknown'
				# get open ports and services for host
				# [k.attrib for k in host.findall('./ports//port//')]
				host = Host(ip_address, macaddr, vendor, hostname, starttime, endtime, self.file_id, scanid)
				hosts.append(host)
			#ip_addresses = [k.find("address[@addrtype='ipv4']").get('addr') for k in hosts_]
			#hostnames = [k.find('.//hostname') for k in hosts_]
		else:
			logger.warning(f'[?] {self} not valid?')
		if len(hosts) == 0 :
			logger.warning(f'[?] {self} no hosts! not valid?')
		return hosts

class Scan(Base):
	__tablename__ = 'scans'
	scan_id = Column(Integer, primary_key=True)
	file_id = Column(Integer, ForeignKey('xmlfiles.file_id'))
	scan_date_todb = Column(String(255))
	valid = Boolean
	scan_count = Column(Integer)
	def __init__(self, file_id, scan_date_todb):
		self.file_id = file_id
		self.scan_date_todb = scan_date_todb
		self.valid = True
		self.scan_count = 0

	def __repr__(self):
		return f'Scan id={self.scan_id} fileid={self.file_id} sdtodb={self.scan_date_todb} '

class Host(Base):
	__tablename__ = 'hosts'
	host_id = Column(Integer, primary_key=True)
	xml_id = Column(Integer)
	ip_address = Column(String(255))
	mac_address = Column(String(255))
	vendor = Column(String(255))
	hostname = Column(String(255))
	starttime = Column(String(255))
	endtime = Column(String(255))
	first_seen = Column(String(255))
	last_seen = Column(String(255))
	first_seen_scan_id = Column(Integer)
	last_seen_scan_id = Column(Integer)
	last_seen_xml_id = Column(Integer)
	scan_count = Column(Integer)
	refresh_count = Column(Integer)

	def __init__(self, ip_address, mac_address, vendor, hostname, starttime,endtime, xml_id, scanid):
		self.first_seen_scan_id = scanid		
		self.xml_id = xml_id
		self.ip_address = ip_address
		self.mac_address = mac_address
		self.vendor = vendor
		self.hostname = hostname
		self.starttime = starttime
		self.endtime = endtime
		self.first_seen = datetime.now()
		self.last_seen = self.first_seen
		self.scan_count = 1
		self.refresh_count = 0

	def __repr__(self):
		return f'<Host id: {self.host_id} xmlid:{self.xml_id} ipv4:{self.ip_address} hostname:{self.hostname}>'

	def refresh_x(self, xmlfileid, scanid):
		self.refresh_count += 1
		self.last_seen_xml_id = xmlfileid
		self.last_seen_scan_id = scanid

	def refresh(self, xmlfile:XMLFile, scan:Scan) -> None:
		self.last_seen_scan_id = scan.scan_id
		self.last_seen_xml_id = xmlfile.file_id
		self.refresh_count += 1
		logger.debug(f'{self} refresh lssid:{self.last_seen_scan_id} lsxid:{self.last_seen_xml_id} rc:{self.refresh_count}  xml={xmlfile.file_id} scan sid={scan.scan_id} sfid={scan.file_id} ')
class Ports(Base):
	__tablename__ = 'ports'
	port_id = Column(Integer, primary_key=True)
	portnumber = Column(Integer)
	service = Column(String(255))
	first_seen = Column(String(255))
	last_seen = Column(String(255))
	def __init__(self, portnumber, service, first_seen):
		#self.ip_address = ip_address
		self.first_seen = first_seen
		self.last_seen = self.first_seen
		self.service = service

class LogEntry(Base):
	__tablename__ = 'scanlog'
	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer)#, ForeignKey('scans.scan_id'))
	host_id = Column(Integer)#, ForeignKey('hosts.port_id'))
	port_id = Column(Integer)#, ForeignKey('ports.host_id'))

	date = Column(String(255))
	def __init__(self, scan_id, host_id, port_id, date):
		self.scan_id = scan_id
		self.host_id = host_id
		self.port_id = port_id
		self.date = date

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


def check_existing_xml(session, filename):
	#sql = text(f"select * from scans where xmlfilename = '{xmlfile}'")
	if not session or not filename:
		logger.error(f'[db] missing session or xmlfile')
		return False
	res = session.query(Scan).filter(Scan.filename == filename).all()
	if len(res) == 0:
		return False
	else:
		return True


def get_hostid(session, ip_address):
	sql = f"select hostid from hosts where ip = '{ip_address}'"
	res = []
	try:
		res = session.execute(sql).fetchone()[0]
	except:
		pass
	if res is None:
		return []
	return res

def get_host(session, ip_address):
	sql = f"select * from hosts where ip = '{ip_address}'"
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

def xmlscan_to_database(scan:Scan=None, xmlfile=None, check=True, session=None):
	if not session:
		logger.error(f'[xmltodb] missing session')
		return
	logger.debug(f'[xmltodb] scan: {scan} xml={xmlfile}')
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
		scan = session.query(Scan).filter(Scan.scanid == scan.scanid).first()
		for host in scan.getHosts():
			host.scanid = scan.scanid
			if len(host.portlist) == 0:
				noportcount += 1
				#host.openports = 0
				#host.ports = 0
				#host.services = 0
			# else:
			portlist = str([f'{k.portnumber}' for k in host.portlist]).replace('[','').replace(']','')
			host.openports = len(portlist.split(','))
			#host.openports = len(host.ports)
			# servicelist = str([k for k in host.services]).replace('[','').replace(']','')
			servicelist = str([f'{k.name} {k.portnumber}' for k in host.services]).replace('[','').replace(']','')
			host.portlist = portlist
			host.servicelist = servicelist
			hcheck = len(get_host(session, host.ip))
			if hcheck == 0:
				logger.debug(f'[todb] hcheck {hcheck} host:{host} ')
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
				logger.debug(f'[todb] hcheck {hcheck} host:{host} hostid={hostid} ')
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
				stmt = update(Host).where(Host.hostid == hostid).values(lastseen=host.lastseen, portlist=portlist, servicelist=servicelist)
				session.execute(stmt)
				hostupdatecount += 1
				#session.query(Host).filter(Host.hostid == hostid).update({"lastseen": scan.scandate})


				ports_ = [session.add(k) for k in host.portlist]
				logger.debug(f'[todb] hostid={hostid} ports={len(ports_)}')
				session.commit()
				for p in session.query(Ports).filter(Ports.hostid == hostid).all():
					portcheck = get_hostport(session=session, portnumber=p.portnumber, hostid=hostid)
					logger.debug(f'[todb] p={p} portcheck = {portcheck} hostid={hostid} ports={len(ports_)}')
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
						stmt = update(Ports).where(Ports.portnumber == p.portnumber).where(Ports.hostid == hostid).values(lastseen=p.lastseen, servicename=p.servicename, product=p.product, extra=p.extra, version=p.version, ostype=p.ostype)
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


