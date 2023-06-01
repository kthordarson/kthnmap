#!/usr/bin/python3
# todo create history table for each ip/scan
from loguru import logger
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser
from configparser import ConfigParser
from sqlalchemy import Engine, text, cast, extract, func
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session)
from subprocess import Popen, PIPE
from concurrent.futures import (ProcessPoolExecutor, ThreadPoolExecutor, as_completed)
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from multiprocessing import cpu_count, Pool
from threading import Thread
from datetime import datetime
from modules.database import get_engine
MAX_WORKERS = cpu_count()
from modules.nmap import Scan, Host, Port, XMLFile,LogEntry, db_init, InvalidXMLFile
VERSION = "0.1.3"
RELEASE_DATE = "2023-03-11"
NMAP_BINARY = '/usr/local/bin/nmap' if os.sys.platform == 'linux' else 'c:/apps/nmap/nmap.exe'
ADDRESS_FILE = 'iplist2.txt'
PORTLIST_FILE = 'portlist.txt'
LOGFILE = 'nmaparser.log'

def exec_nmap(addr, ports):
	port_list = ''.join([k for k in ports])
	xmlout = f'scan-{addr}-{datetime.now()}.xml'.replace(':','').replace(' ','').replace('/','-')
	cmdstr = [NMAP_BINARY,  addr, '-oX', xmlout, '-sV', '-p', port_list] # '--unprivileged',
	out, err = Popen(cmdstr, stdout=PIPE, stderr=PIPE).communicate()
	res = {'out':out.decode('utf-8'),'err':err.decode('utf-8'),'xmlfilename':xmlout}
	logger.info(f'[nmapres] filename={xmlout} addr={addr} res={len(res)} stdout:{len(out)} stderr:{len(err)} ')
	with open(LOGFILE, 'a') as f:
		f.write(f'{xmlout}\n')
		f.write(f'err: {err.decode("utf-8")}\n')
	return res


def run_nmap(session):
	with open(ADDRESS_FILE, 'r') as f:
		addr_ = f.readlines()
	addr_list = [k.strip() for k in addr_]
	with open(PORTLIST_FILE, 'r') as f:
		ports = f.readlines()
	nmapres = []
	futures = []
	with ProcessPoolExecutor(MAX_WORKERS) as executor:
		for addr in addr_list:
			nmap_task = executor.submit(exec_nmap, addr, ports)
			futures.append(nmap_task)
			logger.debug(f'[+] tasks={len(futures)} nmap scans started addr={addr}')
		for future in as_completed(futures):
			r = future.result()
			nmapres.append(r)
			logger.debug(f'[+] task {future} done tasks={len(futures)} r={len(r)} nmapres={len(nmapres)}')
	return nmapres


def scan_path(xmllist:list, engine:Engine, dbtype:str):
	engine = get_engine(dbtype)
	Session = sessionmaker(bind=engine, autoflush=False)
	results = []
	with Session() as session:
		db_xmlfiles = session.query(XMLFile).all()
		db_xmlfilenames = [k.xml_filename for k in db_xmlfiles]
		new_xmlfiles = [k for k in xmllist if k not in [x.xml_filename for x in session.query(XMLFile).all()]]
		if len(new_xmlfiles) == 0 :
			logger.info(f'[SP] no new xml files to scan db_xmlfiles={len(db_xmlfiles)} db_xmlfilenames={len(db_xmlfilenames)} {engine}')
		else:
			for idx,xmlf in enumerate(new_xmlfiles):
				db_xml = None
				t0 = datetime.now()
				try:
					db_xml = XMLFile(xmlf)
					#logger.info(f'[spstart] {idx}/{len(new_xmlfiles)} {xmlf}')
				except InvalidXMLFile as e:
					logger.error(f'[!] {e} file:{xmlf}')
					os.rename(xmlf, f'{xmlf}.invalid')
					continue
				results.append(db_xml)
	return results

def send_hosts_to_db(db_xml_id:int, scan_id:int,  dbtype:str):
	# logger.info(f'[sp] {db_xml} returned {len(xml_hosts)} hosts from {xmlf}')
	engine = get_engine(dbtype)
	Session = sessionmaker(bind=engine, autoflush=False)
	#session = Session()
	t0 = datetime.now()
	newhosts_counter = 0
	refresh_counter = 0
	port_counter = 0
	xml_hosts = None
	with Session() as session:
		db_xml = session.query(XMLFile).filter(XMLFile.file_id == db_xml_id).first()
		if not db_xml.valid:
			logger.warning(f'[send2db] [!] db_xml not valid {db_xml}')
			return 0,0
		scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
		# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} db_xml_id={db_xml_id} scanid={scan_id} scan:{scan}')
		try:
			xml_hosts = db_xml.get_hosts(scan_id)
		except InvalidXMLFile as e:
			errmsg = f'[send2db] [!] InvalidXMLFile {e} db_xml:{db_xml.xml_filename}'
			logger.error(errmsg)
			os.rename(db_xml.xml_filename, f'{db_xml.xml_filename}.invalid')
			raise e
		if len(xml_hosts) == 0:
			logger.warning(f'[send2db] [!] db_xml not valid {db_xml} no xml_hosts')
			return 0,0
		db_hosts = session.query(Host).all()
		for idx, xhost in enumerate(xml_hosts):
			if not db_xml.get_host_ports(xhost.ip_address):
				logger.warning(f'[send2db] {xhost} no ports')
			# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} idx:{idx}/{len(xml_hosts)}')# {xhost.ip_address}')
			if xhost.ip_address in [k.ip_address for k in db_hosts]:
				if len(db_xml.get_host_ports(xhost.ip_address)) == 0:
					logger.warning(f'[send2db] {xhost} no ports')
				# update host
				host_ = session.query(Host).filter(Host.ip_address == xhost.ip_address).first()
				if len(xhost.port_list) != len(host_.port_list):
					#logger.warning(f'[!] checkportlist xhost.port_list:{xhost.port_list} host_.port_list:{host_.port_list}')
					host_.port_list = ','.join(set((xhost.port_list+','+host_.port_list).split(',')))
				refresh_counter += 1
				host_.refresh_count += 1
				host_.last_seen_xml_id = db_xml.file_id
				host_.last_seen_scan_id = scan.scan_id
				#session.commit()
			else:
				#new host
				session.add(xhost)
				xhost.last_seen_xml_id = db_xml.file_id
				xhost.last_seen_scan_id = scan.scan_id
				newhosts_counter += 1
		session.commit()
		db_hosts_count = session.query(Host).filter(Host.file_id==db_xml.file_id).count()
		# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} {db_xml} done db_hosts_count={db_hosts_count}')
		#session.close()
	return db_hosts_count

def send_ports_to_db(db_xml_id:int, scan_id:int, dbtype:str):
	engine = get_engine(dbtype)
	Session = sessionmaker(bind=engine, autoflush=False)
	#session = Session()
	t0 = datetime.now()
	port_counter = 0
	with Session() as session:
		db_xml = session.query(XMLFile).filter(XMLFile.file_id == db_xml_id).first()
		for host in session.query(Host).all():
			hp = db_xml.get_host_ports(host.ip_address)
			host_port_count = 0
			for port in hp:
				pname = port.get('name')
				prod = port.get('product')
				proto = port.get('protocol')
				new_port = Port(portnumber=port.get('portid'), first_seen=str(db_xml.scanstart_str), host_id=host.host_id, scan_id=scan_id, file_id=db_xml.file_id, name=pname, product=prod, protocol=proto)
				session.add(new_port)
				#log_entry = LogEntry(scan_id=scan.scan_id, host_id=host.host_id, port_id=new_port.port_id,timestamp=new_port.first_seen)
				#session.add(log_entry)
				port_counter += 1
				host_port_count += 1
			host.port_count = host_port_count # len(host.port_list.split(','))
		#logger.debug(f'[sh] t:{(datetime.now()-t0).total_seconds()} done db_hosts={db_hosts_count} nhc:{nh_count} rc:{r_count} port_count:{port_count} db_xml:{db_xml}')
		# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} ')
		db_xml.process_time = (datetime.now()-t0).total_seconds()
		session.commit()
		# logger.debug(f'[s2dbports] t:{(datetime.now()-t0).total_seconds()} db_xml.process_time={db_xml.process_time} pc={port_counter}')
	return port_counter


def scan_xml_file(xmlfilename:str, session:sessionmaker, dbtype:str):
	try:
		xml_file = XMLFile(xmlfilename)
	except InvalidXMLFile as e:
		logger.error(e)
		raise e
	session.add(xml_file)
	try:
		session.commit()
	except ProgrammingError as e:
		logger.error(f'[sxf] {e}\n\tDuring commit xml_file = {xml_file} {type(xml_file)}')
		logger.warning(f'xmlfilename={xmlfilename} {type(xmlfilename)}')
		session.rollback()
		return None
	scan = Scan(xml_file.file_id, datetime.now())
	session.add(scan)
	session.commit()
	hosts = xml_file.get_hosts(scan.scan_id)
	db_hostcount = send_hosts_to_db(xml_file.file_id, scan.scan_id, dbtype)
	scan = session.query(Scan).filter(Scan.scan_id == scan.scan_id).first()
	scan.host_count = db_hostcount
	db_portcount = 0
	session.commit()
	logger.debug(f'[sxf] xml:{xml_file.xml_filename} scandate:{xml_file.scandate} scan_id:{scan.scan_id} hosts:{len(hosts)} db_hostcount:{db_hostcount} db_portcount:{db_portcount}') # dbhosts={session.query(Host).count()}')


def refresh_db(session):
	pass

def main():
	parser = OptionParser(usage="%prog [options] --file xmlfile")
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename", action='store', type='string')
	parser.add_option("-p","--path", dest="xmlpath", help="path to xml files")
	parser.add_option("-d","--drop", dest="droptables", help="drop existing data", action="store", default=False)
	parser.add_option("-c","--check", dest="check", help="check existing data", action="store", default=True)
	parser.add_option("-r","--read", dest="readconfig", help="run scan from config", action="store", type='string')
	parser.add_option("--nmap", dest="run_nmap", help="run nmap scan", action="store_true",  default=False)
	parser.add_option("--refresh", dest="refresh_db", help="refresh database", action="store_true",  default=False)
	parser.add_option("--dbtype", dest="dbtype", help="sqlite/mysql/psql", action="store",  default='sqlite')
	parser.add_option("--dbinfo", dest="dbinfo", help="dbinfo", action="store_true")
	(options, args) = parser.parse_args()
	engine = get_engine(options.dbtype)
	Session = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
	session = Session()
	db_init(engine)
	if options.xmlfilename and options.xmlpath:
		parser.error("Please specify either a filename or a path, not both")
		return
	elif options.run_nmap:
		nmap_result = run_nmap(session)
		logger.info(f'[n] nmap_result:{len(nmap_result)}')
	elif options.droptables:
		pass
		#drop_tables()
	# Parse nmap file
	elif options.readconfig:
		# todo read config file, run nmap scan, parse results, pass results to parser and send to database
		pass
	elif options.xmlfilename:
		db_xmlfiles = session.query(XMLFile).all()
		if options.xmlfilename in [k.xml_filename for k in db_xmlfiles]:
			logger.warning(f'[sxf] skipping {options.xmlfilename} already in db')
		else:
			try:
				scan_xml_file(options.xmlfilename, session, options.dbtype)
			except InvalidXMLFile as e:
				logger.error(e)
	elif options.xmlpath:
		t0 = datetime.now()
		xmllist = glob.glob(options.xmlpath + '/*.xml')
		xml_files = scan_path(xmllist, engine, options.dbtype)
		_ = [session.add(xmlfile) for xmlfile in xml_files]
		session.commit()
		_ = [session.add(Scan(xml_file.file_id, datetime.now())) for xml_file in xml_files]
		session.commit()
		logger.info(f'[sp] xml_files={len(xml_files)} dbxml={session.query(XMLFile).count()} dbscan={session.query(Scan).count()}')
		tasks = []
		total_hosts = 0
		total_ports = 0
		with ProcessPoolExecutor(max_workers=2) as executor:
			for xml_file in xml_files:
				scan_id = session.query(Scan).filter(Scan.file_id == xml_file.file_id).first().scan_id
				tasks.append(executor.submit(send_hosts_to_db, xml_file.file_id, scan_id, options.dbtype))
			logger.debug(f'[sp] host send tasks={len(tasks)}')
			rem = len(tasks)
			for idx,task in enumerate(as_completed(tasks)):
				try:
					db_hostcount = task.result()
				except OperationalError as e:
					logger.error(f'[!] {idx}/{len(tasks)} rem:{rem} OperationalError during send_hosts_to_db task:{task}\n{e}')
					session.rollback()
				total_hosts += db_hostcount
				timer = (datetime.now()-t0).total_seconds()
				rem -= 1
				# logger.info(f'[sp] host send task:{idx}/{len(tasks)} rem:{rem} timer:{timer} hostcount={db_hostcount} ')
		timer = (datetime.now()-t0).total_seconds()
		logger.info(f'[sp] send_hosts_to_db done timer:{timer} hosts:{total_hosts}')
		t0 = datetime.now()
		db_xml_files = session.query(XMLFile).all()
		with ProcessPoolExecutor(max_workers=2) as executor:
			for xml_file in db_xml_files:
				scan_id = session.query(Scan).filter(Scan.file_id == xml_file.file_id).first().scan_id
				tasks.append(executor.submit(send_ports_to_db, xml_file.file_id, scan_id, options.dbtype))
			logger.debug(f'[sp] send_ports_to_db tasks={len(tasks)}')
			rem = len(tasks)
			for idx,task in enumerate(as_completed(tasks)):
				try:
					db_portcount = task.result()
				except OperationalError as e:
					logger.error(f'[!] {idx}/{len(tasks)} rem:{rem} OperationalError during send_ports_to_db task:{task}\n{e}')
					session.rollback()
				total_ports += db_portcount
				timer = (datetime.now()-t0).total_seconds()
				rem -= 1
			#logger.info(f'[sp] send_ports_to_db task:{idx}/{len(tasks)} rem:{rem} timer:{timer} portcount={db_portcount} ')
		timer = (datetime.now()-t0).total_seconds()
		logger.info(f'[sp] send_ports_to_db done timer:{timer} ports:{total_ports}')

	elif options.refresh_db:
		refresh_db(session)
	elif options.dbinfo:
		all_hosts = session.query(Host).all()
		print(f'hosts={session.query(Host).count()} ports={session.query(Port).count()} logentries={session.query(LogEntry).count()} scans={session.query(Scan).count()} xmlfiles={session.query(XMLFile).count()}')
		for host in all_hosts:
			logentries = session.query(LogEntry).filter(LogEntry.host_id == host.host_id).count()
			port_entries = session.query(Port).filter(Port.host_id == host.host_id).count()
			try:
				l = [(k.host_id, k.timestamp, k.count) for k in session.query(LogEntry.log_id, LogEntry.host_id, LogEntry.timestamp, func.count(LogEntry.host_id).label('count')).filter(LogEntry.host_id==host.host_id).group_by(func.day(LogEntry.timestamp)).group_by(LogEntry.host_id).all()]
			except OperationalError as e:
				logger.error(e)
				l = []
			if len(l)>3:
				print(f'host {host.ip_address} l={logentries} p={port_entries} {len(l)}')

if __name__ == "__main__":
	main()
# [(k.host_id, k.timestamp, k.count) for k in session.query(LogEntry.log_id, LogEntry.host_id,LogEntry.timestamp, func.count(LogEntry.host_id).label('count')).filter(LogEntry.host_id==10).group_by(func.month(LogEntry.timestamp)).group_by(LogEntry.host_id).all()]
# session.query(LogEntry.log_id, LogEntry.host_id,LogEntry.timestamp, func.count(LogEntry.host_id).label('count')).filter(LogEntry.host_id==10).group_by(func.month(LogEntry.timestamp)).group_by(LogEntry.host_id).all()
# [k for k in session.query(LogEntry.log_id.label('logid'),LogEntry.timestamp, func.count(LogEntry.log_id).label('count')).filter(LogEntry.host_id==10).group_by(func.day(LogEntry.timestamp)).filter_by()]
# l0 = session.query(LogEntry, func.count(LogEntry.log_id).label('count')).filter(LogEntry.host_id==10).group_by(func.day(LogEntry.timestamp)).all()
# len([k for k in session.query(LogEntry.timestamp, func.count(LogEntry.log_id).label('count')).group_by(LogEntry.timestamp).order_by(LogEntry.timestamp).filter_by()])
# logs grouped....
# session.query(func.DATE(Host.first_seen)).distinct().all()
# session.query(func.DATE(LogEntry.timestamp)).distinct().all()
# session.query(LogEntry).group_by(func.date_format(LogEntry.timestamp, '%H')).all()
# session.query(LogEntry).group_by(func.year(LogEntry.timestamp), func.month(LogEntry.timestamp)).all()
#session.query(LogEntry, func.count(LogEntry.log_id).label('count')).group_by(func.day(LogEntry.timestamp)).all()
# session.query(func.count(LogEntry.host_id), extract('year', LogEntry.timestamp), extract('month', LogEntry.timestamp)).group_by(extract('month',LogEntry.timestamp), LogEntry.host_id).all()
#  'select (select count(*) from hosts) as hc, (select count(*) from scans) as sc, (select count(*) from ports) as pc'
# mysql -h elitedesk -u root -pfoobar9999 nmapscans -e 'select (select count(*) from xmlfiles) as xc, (select count(*) from hosts) as hc, (select count(*) from scans) as sc, (select count(*) from ports) as pc'