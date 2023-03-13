#!/usr/bin/python3
# todo create history table for each ip/scan
from loguru import logger
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser
from configparser import ConfigParser
from sqlalchemy import Engine
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session)
from subprocess import Popen, PIPE
from concurrent.futures import (ProcessPoolExecutor, ThreadPoolExecutor, as_completed)
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from multiprocessing import cpu_count, Pool
from threading import Thread
from datetime import datetime
from modules.database import get_engine
MAX_WORKERS = cpu_count()
from modules.nmap import Scan, Host, Port, XMLFile, db_init, InvalidXMLFile
VERSION = "0.1.3"
RELEASE_DATE = "2023-03-11"
NMAP_BINARY = '/usr/local/bin/nmap'
ADDRESS_FILE = 'iplist2.txt'
PORTLIST_FILE = 'portlist2.txt'
LOGFILE = 'nmaparser.log'

def exec_nmap(addr, ports):
	portlist = ''.join([k for k in ports])
	xmlout = f'scan-{addr}-{datetime.now()}.xml'.replace(':','').replace(' ','').replace('/','-')
	cmdstr = [NMAP_BINARY,  addr, '-oX', xmlout, '-sV', '-p', portlist] # '--unprivileged',
	out, err = Popen(cmdstr, stdout=PIPE, stderr=PIPE).communicate()
	res = {'out':out.decode('utf-8'),'err':err.decode('utf-8'),'xmlfilename':xmlout}
	logger.info(f'[nmapres] addr={addr} res={len(res)} stdout/err={len(out)}/{len(err)} filename={xmlout} ')
	with open(LOGFILE, 'a') as f:
		f.write(f'{xmlout}\n')
		f.write(f'err: {err.decode("utf-8")}\n')
	return res

def db_scan(scan, session):
	pass


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
			nmapres.append(future.result())
	return nmapres


def scan_path(xmllist:list, engine:Engine, dbtype:str):
	engine = get_engine(dbtype)
	Session = sessionmaker(bind=engine)
	xtasks = []
	send_threads = []
	with Session() as session:
		db_xmlfiles = session.query(XMLFile).all()
		db_xmlfilenames = [k.xml_filename for k in db_xmlfiles]
		new_xmlfiles = [k for k in xmllist if k not in [x.xml_filename for x in session.query(XMLFile).all()]]
		if len(new_xmlfiles) == 0 :
			logger.info(f'[SP] no new xml files to scan db_xmlfiles={len(db_xmlfiles)} db_xmlfilenames={len(db_xmlfilenames)} {engine}')
		else:
			for xmlf in new_xmlfiles:
				db_xml = XMLFile(xmlf)
				session.add(db_xml)
				session.commit()
				scan = Scan(db_xml.file_id, datetime.now())
				session.add(scan)
				session.commit()
				send_hosts_to_db(db_xml.file_id, scan.scan_id, session, dbtype)


def send_hosts_to_db(db_xml_id:int, scan_id:int, session:sessionmaker, dbtype:str):
	# logger.info(f'[sp] {db_xml} returned {len(xml_hosts)} hosts from {xmlf}')
	result = []
	engine = get_engine(dbtype)
	Session = sessionmaker(bind=engine)
	session = Session()
	t0 = datetime.now()
	nh_count = 0
	r_count = 0
	port_count = 0
	db_xml = session.query(XMLFile).filter(XMLFile.file_id == db_xml_id).first()
	if db_xml.valid:
		scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
		try:
			xml_hosts = db_xml.get_hosts(scan.scan_id)
		except InvalidXMLFile as e:
			errmsg = f'[!] InvalidXMLFile {e} db_xml:{db_xml.xml_filename}'
			logger.error(errmsg)
			return errmsg
		db_hosts = session.query(Host).all()

		for xhost in xml_hosts:
			if xhost.ip_address in [k.ip_address for k in db_hosts]:
				#xhost.refresh(db_xml.file_id, scan.scan_id)
				r_count += 1
			else:
				session.add(xhost)
				nh_count += 1
		db_xml.process_time = (datetime.now()-t0).total_seconds()
		session.commit()
		# db_hosts_count = session.query(Host).count()
		for host in session.query(Host).all():
			hp = db_xml.get_host_ports(host.ip_address)
			for port in hp:
				pname = port.get('name')
				prod = port.get('product')
				proto = port.get('protocol')
				new_port = Port(portnumber=port.get('portid'), first_seen=str(db_xml.scanstart_str), host_id=host.host_id, scan_id=scan.scan_id, file_id=db_xml.file_id, name=pname, product=prod, protocol=proto)
				session.add(new_port)
				port_count += 1
		#logger.debug(f'[sh] t:{(datetime.now()-t0).total_seconds()} done db_hosts={db_hosts_count} nhc:{nh_count} rc:{r_count} portcount:{port_count} db_xml:{db_xml}')
		session.commit()
		session.close()
		return 'ok'


def scan_filex(xmlfilename:str, session:sessionmaker):
	nmapxml = XMLFile(xmlfilename)
	scan = Scan(nmapxml.file_id, datetime.now())
	logger.info(f'[sf] nmapxml:{nmapxml} {nmapxml.scandate} scan:{scan}')
	return nmapxml, scan

def scan_xml_file(xmlfilename:str, session:sessionmaker, dbtype:str):
	xml_file = XMLFile(xmlfilename)
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
	logger.debug(f'[sxf] nmap_xml_id:{xml_file.file_id} scandate:{xml_file.scandate} scan_id:{scan.scan_id} hosts:{len(hosts)} ') # dbhosts={session.query(Host).count()}')
	send_hosts_to_db(xml_file.file_id, scan.scan_id, session, dbtype)


def refresh_db(session):
	all_hosts = session.query(Host).all()
	for host in all_hosts:
		host.refresh()
	session.commit()


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
	(options, args) = parser.parse_args()
	engine = get_engine(options.dbtype)
	Session = sessionmaker(bind=engine, expire_on_commit=False)
	session = Session()
	db_init(engine)
	if options.xmlfilename and options.xmlpath:
		parser.error("Please specify either a filename or a path, not both")
		return
	elif options.run_nmap:
		print('running nmap')
		nmap_result = run_nmap(session)
		for n in nmap_result:
			print(n)
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
			scan_xml_file(options.xmlfilename, session, options.dbtype)
	elif options.xmlpath:
		xmllist = glob.glob(options.xmlpath + '/*.xml')
		scan_path(xmllist, engine, options.dbtype)
	elif options.refresh_db:
		refresh_db(session)

if __name__ == "__main__":
	main()



