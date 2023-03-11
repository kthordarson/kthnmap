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
	logger.info(f'dbinit {engine.name}')
	Base.metadata.create_all(bind=engine)
class Donk():
	def __init__(self):
		self.donk = 'donk'
		self.root = 'root'
class XMLFile(Base):
	__tablename__ = 'xmlfiles'
	file_id = Column(Integer, primary_key=True)
	xml_filename = Column(String(255))
	scandate = Column(String(255))
	scanner = Column(String(255))
	scanstart_str = Column(String(255))
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
		except Exception as e:
			logger.error(f'[X] {e} {type(e)} file:{filename}')
			self.valid = False

	def __repr__(self):
		return f'<XMLFile id:{self.file_id} xml_filename:{self.xml_filename} scanner:{self.scanner} sd:{self.scandate}> '

	def et_xml_parse(self):
		try:
			xmldata = ET.parse(self.xml_filename)
			root = xmldata.getroot()
			self.valid = True
			self.scanner = root.attrib['scanner']
			self.scandate =root.attrib['start']
			self.scanstart_str = root.attrib['startstr']
			self.scanargs = root.attrib['args'][:255]
			return root
		except ParseError as e:
			errmsg = f'[!] Error {e} while parsing self.xml_filename={self.xml_filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		except TypeError as e:
			errmsg = f'[!] TypeError {e} while parsing self.xml_filename={self.xml_filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)
		except AttributeError as e:
			errmsg = f'[!] AttributeError {e} while parsing self.xml_filename={self.xml_filename}'
			self.valid = False
			raise InvalidXMLFile(errmsg)

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
		try:
			ports = [k for k in self.root.find(f".//*[@addr='{ip_addr}']../ports")]
		except TypeError as e:
			#logger.error(f'{e} ip_addr:{ip_addr}')
			return []
		# create port dict for each port
		hp = []
		for p in ports:
			if p.tag != 'extraports':
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
				hosts_ = self.root.findall('.//host/.')
			except AttributeError as e:
				logger.error(e)
				return None
			if len(hosts_) == 0:
				errmsg = f'[?] {self} hosts_ empty?'
				self.valid = False
				raise InvalidXMLFile(errmsg)
			for h in hosts_:
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
				hp = self.get_host_ports(ip_address)
				try:
					host_portlist = ','.join(k['portid'] for k in hp)
				except TypeError as e:
					logger.warning(e)
					print(hp)
					host_portlist = ''
				host = Host(ip_address, macaddr, vendor, hostname, starttime, endtime, self.file_id, scanid, host_portlist)
				hosts.append(host)
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
	valid = Column(Boolean)
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
	portlist = Column(String(255))
	mac_address = Column(String(255))
	vendor = Column(String(255))
	hostname = Column(String(255))
	starttime = Column(String(255))
	endtime = Column(String(255))
	first_seen = Column(String(255))
	last_seen = Column(String(255))
	scan_id = Column(Integer)
	last_seen_scan_id = Column(Integer)
	last_seen_xml_id = Column(Integer)
	scan_count = Column(Integer)
	refresh_count = Column(Integer)

	def __init__(self, ip_address, mac_address, vendor, hostname, starttime,endtime, xml_id, scanid, portlist):
		self.scan_id = scanid
		self.xml_id = xml_id
		self.ip_address = ip_address
		self.portlist = portlist
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
	first_seen = Column(String(255))
	last_seen = Column(String(255))
	def __init__(self, portnumber:int, first_seen:str, host_id:int, scan_id:int, file_id:int, name:str, product:str, protocol:str):
		self.portnumber = portnumber
		self.file_id = file_id
		self.host_id = host_id
		self.scan_id = scan_id
		#self.ip_address = ip_address
		self.first_seen = first_seen
		self.last_seen = self.first_seen
		self.name = name if name else 'noname'
		self.product = product if product else 'noproduct'
		self.protocol = protocol

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

