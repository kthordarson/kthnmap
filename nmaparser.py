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
	logger.info(f'[nmapres] filename={xmlout} addr={addr} res={len(res)} stdout:{len(out)} stderr:{len(err)} ')
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
			r = future.result()
			nmapres.append(r)
			logger.debug(f'[+] task {future} done tasks={len(futures)} r={len(r)} nmapres={len(nmapres)}')
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
				if db_xml:
					session.add(db_xml)
					session.commit()
					scan = Scan(db_xml.file_id, datetime.now())
					session.add(scan)
					session.commit()
					# logger.info(f'[spscan] {(datetime.now()-t0).total_seconds()} scan:{scan}')
					db_hostcount,db_portcount = send_hosts_to_db(db_xml.file_id, scan.scan_id, session, dbtype)
					# logger.info(f'[spsend] {(datetime.now()-t0).total_seconds()} send done {db_hostcount},{db_portcount}')
					scan = session.query(Scan).filter(Scan.scan_id == scan.scan_id).first()
					scan.host_count = db_hostcount
					scan.port_count = db_portcount
					session.commit()
					#ahc = session.query(Host).count()
					#apc = session.query(Port).count()
					logger.debug(f'[SP] {(datetime.now()-t0).total_seconds()}  {idx}/{len(new_xmlfiles)} ')#bhc={db_hostcount} shc:{scan.host_count} spc:{scan.port_count} {ahc}/{apc}')



def send_hosts_to_db(db_xml_id:int, scan_id:int, session:sessionmaker, dbtype:str):
	# logger.info(f'[sp] {db_xml} returned {len(xml_hosts)} hosts from {xmlf}')
	engine = get_engine(dbtype)
	Session = sessionmaker(bind=engine)
	session = Session()
	t0 = datetime.now()
	newhosts_count = 0
	refresh_count = 0
	port_count = 0
	db_xml = session.query(XMLFile).filter(XMLFile.file_id == db_xml_id).first()
	if db_xml.valid:
		scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
		# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} ')
		try:
			xml_hosts = db_xml.get_hosts(scan.scan_id)
		except InvalidXMLFile as e:
			errmsg = f'[send2db] [!] InvalidXMLFile {e} db_xml:{db_xml.xml_filename}'
			logger.error(errmsg)
			os.rename(db_xml.xml_filename, f'{db_xml.xml_filename}.invalid')
			raise e
		db_hosts = session.query(Host).all()

		for idx, xhost in enumerate(xml_hosts):
			# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} idx:{idx}/{len(xml_hosts)}')# {xhost.ip_address}')
			if xhost.ip_address in [k.ip_address for k in db_hosts]:
				#xhost.refresh(db_xml.file_id, scan.scan_id)
				host_ = session.query(Host).filter(Host.ip_address == xhost.ip_address).first()
				refresh_count += 1
				host_.refresh_count += 1
				host_.scan_count += 1
				host_.last_seen_xml_id = db_xml.file_id
				host_.last_seen_scan_id = scan.scan_id
				#session.commit()
			else:
				session.add(xhost)
				xhost.refresh_count += 1
				xhost.scan_count += 1
				xhost.last_seen_xml_id = db_xml.file_id
				xhost.last_seen_scan_id = scan.scan_id
				newhosts_count += 1
		# db_hosts_count = session.query(Host).count()
		#logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} ')
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
		# logger.info(f'[send2db] timer: {(datetime.now()-t0).total_seconds()} ')
		db_xml.process_time = (datetime.now()-t0).total_seconds()
		session.commit()
		r_hostcount = session.query(Host).filter(Host.scan_id == scan.scan_id).count()
		r_portcount = session.query(Port).filter(Port.scan_id == scan.scan_id).count()
		logger.debug(f'[send2db] t:{(datetime.now()-t0).total_seconds()} rhc={r_hostcount} rpc={r_portcount} xh={len(xml_hosts)} dbh={len(db_hosts)} pc={port_count}')
		return r_hostcount, r_portcount


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
	db_hostcount, db_portcount = send_hosts_to_db(xml_file.file_id, scan.scan_id, session, dbtype)
	scan = session.query(Scan).filter(Scan.scan_id == scan.scan_id).first()
	scan.host_count = db_hostcount
	scan.port_count = db_portcount
	session.commit()
	logger.debug(f'[sxf] xml:{xml_file.xml_filename} scandate:{xml_file.scandate} scan_id:{scan.scan_id} hosts:{len(hosts)} db_hostcount:{db_hostcount} db_portcount:{db_portcount}') # dbhosts={session.query(Host).count()}')


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
		xmllist = glob.glob(options.xmlpath + '/*.xml')
		scan_path(xmllist, engine, options.dbtype)
	elif options.refresh_db:
		refresh_db(session)

if __name__ == "__main__":
	main()



