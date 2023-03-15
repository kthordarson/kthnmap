from sqlalchemy import create_engine, MetaData, Column, Integer, Float, String, DateTime, Date, Boolean, ForeignKey, text, update
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

class InvalidXMLFile(Exception):
	pass

class Base(DeclarativeBase):
	pass

def db_init(engine: Engine) -> None:
	# logger.info(f'dbinit {engine.name}')
	Base.metadata.create_all(bind=engine)

class XMLFile(Base):
	__tablename__ = 'xmlfiles'
	file_id = Column(Integer, primary_key=True)
	xml_filename = Column(String(255))
	scandate = Column(DateTime)
	scanner = Column(String(255))
	scanstart_str = Column(DateTime)
	scanargs = Column(String(512))
	valid = Column(Boolean)
	read_count = Column(Integer)
	process_time = Column(Float)

	def __init__(self, filename:str):
		self.xml_filename = filename
		self.valid = False
		self.xmldata = None
		self.hostlist = []
		self.read_count = 0
		self.scandate = None
		self.scanner = None
		self.scanstart_str = None
		self.scanargs = None
		self.process_time = 0.0
		try:
			self.root = self.et_xml_parse()
		except InvalidXMLFile as e:
			errmsg = f'[X] InvalidXMLFile {e} file: {filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		except Exception as e:
			logger.error(f'[X] unhandled exception {e} {type(e)} file: {filename}')
			self.valid = False

	def __repr__(self):
		return f'<XMLFile id:{self.file_id} xml_filename:{os.path.basename(self.xml_filename)} scanner:{self.scanner} sd:{self.scandate} valid:{self.valid}> '

	def et_xml_parse(self):
		root = []
		try:
			xmldata = ET.parse(self.xml_filename)
			root = xmldata.getroot()
			self.valid = True
		except ParseError as e:
			errmsg = f'[!] ParseError {e} while parsing {self.xml_filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		except TypeError as e:
			errmsg = f'[!] TypeError {e} while parsing {self.xml_filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		except AttributeError as e:
			errmsg = f'[!] AttributeError {e} while parsing {self.xml_filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		try:
			self.scanner = root.attrib['scanner']
		except Exception as e:
			logger.error(f'[!] {e} parsing scanner from {self.xml_filename}')
		try:
			self.scandate = datetime.fromtimestamp(int(root.attrib['start']))
		except Exception as e:
			logger.error(f'[!] {e} parsing scandate from {self.xml_filename}')
		try:
			self.scanstart_str = datetime.strptime(root.attrib['startstr'], '%a %b %d %H:%M:%S %Y')
		except Exception as e:
			logger.error(f'[!] {e} parsing scanstart_str from {self.xml_filename}')
		try:
			self.scanargs = root.attrib['args'][:255]
		except Exception as e:
			logger.error(f'[!] {e} parsing scanargs from {self.xml_filename}')
		return root

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

	def get_host(self, ip_addr):
		# h = self.root.find(f".//host/*[@addr='{ip_addr}']..//")
		h = self.root.findall(f".//*[@addr='{ip_addr}']..//")
		return h

	def get_host_ports(self, ip_addr):
		#h = self.get_host(ip_addr)
		#hp = [k.attrib for k in h if k.tag=='port']
		# root = self.et_xml_parse()
		ports = []
		try:
			self.root = self.et_xml_parse()
			ports = self.root.find(f".//*[@addr='{ip_addr}']../ports") or []
		except TypeError as e:
			logger.error(f'{e} ip_addr:{ip_addr}')
			return []
		# create port dict for each port
		hp = []
		# ports = [k for k in ports_ if k.find('state').get('state') =='filtered']
		for p in [k for k in ports if k.tag =='port']:
			#print(f'p:{p}')
			chk = p.find('state').get('state')
			#print(f'chk:{chk}')
			if chk =='open':
				p_portid = p.get('portid')
				if not p_portid:
					logger.warning(f'[!] no portid found for {p} ipaddr:{ip_addr}')
					continue
				p_protocol = p.get('protocol')
				if p.find('service'):
					p_name = p.find('service').get('name')
				else:
					p_name = ''
				if p.find('service'):
					p_product = p.find('service').get('product')
				else:
					p_product = ''
				pitem = {
					'portid': p_portid,
					'protocol': p_protocol,
					'name' : p_name,
					'product' : p_product
				}
				hp.append(pitem)
		return hp

	def get_hosts(self, scanid):
		hosts = []
		if self.valid:
			self.root = self.et_xml_parse()
			try:
				#hosts_ = self.root.findall('.//host/.')
				hosts_ = [h for h in self.root.findall('./host') if h.get('starttime')]
			except AttributeError as e:
				errmsg = f'[gh] {self} {e} scanid:{scanid}'
				self.valid = False
				raise InvalidXMLFile(errmsg)
			if len(hosts_) == 0:
				errmsg = f'[?] {self} hosts_ empty?'
				self.valid = False
				raise InvalidXMLFile(errmsg)
			for h in hosts_:
				starttime = h.get('starttime')
				if not starttime:
					errmsg = f'[!] no starttime found for {h} xml_filename:{self.xml_filename}'
					self.valid = False
					raise InvalidXMLFile(errmsg)
				endtime = h.get('endtime')
				if not endtime:
					errmsg = f'[!] no endtime found for {h}'
					self.valid = False
					raise InvalidXMLFile(errmsg)
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
				hp = self.get_host_ports(ip_address)
				host_portlist = ''
				if hp:
					try:
						host_portlist = ','.join(k['portid'] for k in hp)
					except TypeError as e:
						raise InvalidXMLFile(e)
				if len(host_portlist) >0:
					try:
						host = Host(ip_address, macaddr, vendor, hostname, starttime, endtime, self.file_id, scanid, host_portlist)
						hosts.append(host)
					except TypeError as e:
						errmsg = f'[!] {e} h:{h} starttime:{starttime} endtime:{endtime} ip_address:{ip_address} vendor:{vendor} macaddr:{macaddr} hostname:{hostname} hp:{hp} host_portlist:{host_portlist}'
						raise InvalidXMLFile(errmsg)
		else:
			errmsg = f'[?] {self} not valid?'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		if len(hosts) == 0 :
			errmsg = f'[?] {self} no hosts! not valid?'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		return hosts

class Scan(Base):
	__tablename__ = 'scans'
	scan_id = Column(Integer, primary_key=True)
	file_id = Column(Integer, ForeignKey('xmlfiles.file_id'))
	scan_date_todb = Column(DateTime)
	host_count = Column(Integer)
	port_count = Column(Integer)
	def __init__(self, file_id, scan_date_todb):
		self.file_id = file_id
		self.scan_date_todb = scan_date_todb
		self.host_count = 0
		self.port_count = 0

	def __repr__(self):
		return f'<Scan id={self.scan_id} fileid={self.file_id} hc:{self.host_count} pc:{self.port_count}>'

class Host(Base):
	__tablename__ = 'hosts'
	host_id = Column(Integer, primary_key=True)
	file_id = Column(Integer)
	ip_address = Column(String(255))
	port_list = Column(String(255))
	port_count = Column(Integer)
	mac_address = Column(String(255))
	vendor = Column(String(255))
	hostname = Column(String(255))
	starttime = Column(String(255))
	endtime = Column(String(255))
	first_seen = Column(DateTime)
	last_seen = Column(DateTime)
	scan_id = Column(Integer)
	last_seen_scan_id = Column(Integer)
	last_seen_xml_id = Column(Integer)
	refresh_count = Column(Integer)

	def __init__(self, ip_address, mac_address, vendor, hostname, starttime,endtime, file_id, scanid, port_list):
		self.scan_id = scanid
		self.file_id = file_id
		self.ip_address = ip_address
		self.port_list = port_list
		self.port_count = len(port_list.split(','))
		self.mac_address = mac_address
		self.vendor = vendor
		self.hostname = hostname
		self.starttime = datetime.fromtimestamp(int(starttime))
		self.endtime = datetime.fromtimestamp(int(endtime))
		self.first_seen = self.starttime # datetime.now()
		self.last_seen = self.first_seen
		self.refresh_count = 0

	def __repr__(self):
		return f'<Host id: {self.host_id} xmlid:{self.file_id} ipv4:{self.ip_address} hostname:{self.hostname}>'

	def refresh(self, xmlfileid:int, scanid:int) -> None:
		self.refresh_count += 1
		self.last_seen_xml_id = xmlfileid
		self.last_seen_scan_id = scanid

class Port(Base):
	__tablename__ = 'ports'
	port_id = Column(Integer, primary_key=True)
	portnumber = Column(Integer)
	host_id = Column(Integer)
	scan_id = Column(Integer)
	file_id = Column(Integer)
	name = Column(String(255))
	product = Column(String(255))
	protocol = Column(String(255))
	first_seen = Column(DateTime)
	last_seen = Column(DateTime)
	def __init__(self, portnumber:int, first_seen:str, host_id:int, scan_id:int, file_id:int, name:str, product:str, protocol:str):
		self.portnumber = portnumber
		self.file_id = file_id
		self.host_id = host_id
		self.scan_id = scan_id
		#self.ip_address = ip_address
		self.first_seen = datetime.strptime(first_seen,'%Y-%m-%d %H:%M:%S')
		self.last_seen = self.first_seen
		self.name = name if name else 'noname'
		self.product = product if product else 'noproduct'
		self.protocol = protocol if protocol else 'noproto'
	def __repr__(self):
		return f'<Port [ {self.name} ] id:{self.port_id} portnumber:{self.portnumber} s:{self.scan_id} f:{self.file_id} h:{self.host_id} >'

class LogEntry(Base):
	__tablename__ = 'scanlog'
	log_id = Column(Integer, primary_key=True)
	timestamp = Column(DateTime)
	scan_id = Column(Integer, ForeignKey('scans.scan_id'))
	host_id = Column(Integer, ForeignKey('hosts.host_id'))
	port_id = Column(Integer, ForeignKey('ports.port_id'))
	def __init__(self, scan_id, host_id, port_id, timestamp):
		self.scan_id = scan_id
		self.host_id = host_id
		self.port_id = port_id
		self.timestamp = timestamp
	def __repr__(self):
		return f'<Log id:{self.log_id} sid:{self.scan_id} t:{self.timestamp} [ h:{self.host_id}] p:{self.port_id} ]>'

