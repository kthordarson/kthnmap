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
from multiprocessing import cpu_count
from datetime import datetime
from modules.database import get_engine
from modules.nmap import Scan, Host, Port, XMLFile, db_init
from libnmap.parser import NmapParser
MAX_WORKERS = cpu_count()
VERSION = "0.1.2"
RELEASE_DATE = "2023-03-03"
# nmap -iL ~/Documents/samskip/samskipexternal.txt  -oX scanexternal-27022023-01.xml  -sV

class ScanIdNotFound(Exception):
	pass

def exec_nmap(addr, ports):
	# ports = '179,10001,10029,10074,10117,10147,102,10260,1027,10273,111,11211,1194,123,129,137,139,143,1434,14570,1604,161,16418,16419,16422,16423,16440,16441,1645,16458,16459,16493,16512,16513,16526,16527,16622,16623,16678,16679,16684,16696,16697,16701,16710,16711,16733,16890,16891,16894,16895,16897,16940,16941,16952,16953,16964,16965,16994,16995,16996,16997,17,17006,17007,1701,17034,17035,17036,17037,17050,17051,17068,17069,17071,17078,17139,17166,17167,17185,17194,17195,17201,17258,17259,17300,17318,17350,17356,17357,17384,17424,17425,17462,17463,17520,17521,17583,177,1812,19,1900,19132,20087,21,21025,2123,2152,22,2222,22880,23,2362,2425,24287,25,27015,27016,27036,27105,27841,27960,28015,3,30301,30303,30718,32414,32799,3283,3386,3391,3478,3483,34963,3544,36316,3671,3702,37810,37833,3784,389,4000,4070,41630,41794,427,443,44346,445,44818,4500,465,47808,4800,48899,49239,49334,500,5006,5008,502,50253,5050,50569,5060,5061,5070,5093,5094,5095,514,518,520,523,53413,5349,5351,5353,541,54321,5551,55523,5632,5683,5684,6000,623,626,64626,64738,65379,65476,65486,65496,65499,6881,69,6969,7,7400,784,80,8000,8013,8080,8081,8082,8083,8088,81,853,873,88,8888,9034,9201,9302,9600,981,987'
	# xmlout = f'scan-{addr}-{datetime.now()}.xml'
	portlist = ''.join([k for k in ports])
	xmlout = f'scan-{addr}-{datetime.now()}.xml'.replace(':','').replace(' ','').replace('/','-')
	# cmdstr = ['/usr/local/bin/nmap',  addr, '-oX', xmlout, '-sV', '-p', portlist] # '--unprivileged',
	cmdstr = ['/usr/local/bin/nmap',  addr, '-oX', xmlout, '-sV', '-p', portlist] # '--unprivileged',
	out, err = Popen(cmdstr, stdout=PIPE, stderr=PIPE).communicate()
	res = out.decode('utf-8')
	logger.info(f'[nmapres] addr={addr} res={len(res)} stdout/err={len(out)}/{len(err)} filename={xmlout} cmd={cmdstr}')
	return xmlout

def db_scan(scan, session):
	pass


def run_nmap(session):
	address_file = 'iplist2.txt'
	portlist_file = 'portlist2.txt'
	with open(address_file, 'r') as f:
		addr_ = f.readlines()
	addr_list = [k.strip() for k in addr_]
	with open(portlist_file, 'r') as f:
		ports = f.readlines()
	nmapres = []
	futures = []
	with ProcessPoolExecutor(MAX_WORKERS) as executor:
		#futures = [executor.submit(exec_nmap, addr, '-sV -oX -') for addr in addr_list]
		for addr in addr_list:
			nmap_task = executor.submit(exec_nmap, addr, ports)
			futures.append(nmap_task)
			logger.debug(f'[+] tasks={len(futures)} nmap scans started addr={addr}')
		#futures = [executor.submit(exec_nmap, addr, ports) for addr in addr_list]

		for future in as_completed(futures):
			xml_filename = future.result()
			try:
				nmap_xml = XMLFile(xml_filename)
			except AttributeError as e:
				logger.error(f'[!] xml_filename={xml_filename} error={e}')
				continue
			session.add(nmap_xml)
			session.commit()
			scan = Scan(nmap_xml.file_id, datetime.now())
			session.add(scan)
			session.commit()
			hosts = nmap_xml.get_hosts(scan.scan_id)
			logger.info(f'xml_filename={xml_filename} scan={scan} nx={nmap_xml} sending {len(hosts)} hosts to db')
			for host in hosts:
				newhost = Host(host)
	return nmapres


def scan_path(xmllist:list, session:sessionmaker):
	#xmllist = glob.glob(options.xmlpath + '/*.xml')
	db_xmlfiles = session.query(XMLFile).all()
	db_xmlfilenames = [k.xml_filename for k in db_xmlfiles]
	#new_xmlfiles = list(set(xmllist).symmetric_difference(set(db_xmlfilenames)))
	new_xmlfiles = [k for k in xmllist if k not in [x.xml_filename for x in session.query(XMLFile).all()]]
	if len(new_xmlfiles) == 0 :
		logger.info(f'[SP] no new xml files to scan....')
	else: # len(new_xmlfiles) > 0:
		logger.debug(f'[SP] db_xmlfiles={len(db_xmlfiles)} xmlpath found {len(xmllist)} files, new xml files = {len(new_xmlfiles)}')
		for xmlf in new_xmlfiles:
			db_xml = XMLFile(xmlf)
			session.add(db_xml)
			session.commit()
			scan = Scan(db_xml.file_id, datetime.now())
			session.add(scan)
			session.commit()
			send_hosts_to_db(db_xml, scan, session)

def send_hosts_to_db(db_xml:XMLFile, scan:Scan, session:sessionmaker):
	# logger.info(f'[sp] {db_xml} returned {len(xml_hosts)} hosts from {xmlf}')
	t0 = datetime.now()
	nh_count = 0
	r_count = 0
	xml_hosts = db_xml.get_hosts(scan.scan_id)
	if len(xml_hosts) == 0:
		logger.warning(f'[sh] no xml_hosts from db_xml:{db_xml}')
	else:
		db_hosts = session.query(Host).all()
		#_ = [k.refresh_x(db_xml.file_id, scan.scan_id) for k in db_hosts]
		xml_iplist = [k.ip_address for k in xml_hosts]
		db_iplist = [k.ip_address for k in db_hosts]
		#ipaddr_list = list(set(xml_iplist).symmetric_difference(set(db_iplist)))
		#new_xml_hosts = [k for k in xml_hosts if k.ip_address not in ipaddr_list]
		new_xml_hosts = set(xml_iplist) - set(db_iplist)
		logger.info(f'[sh] t:{(datetime.now()-t0).total_seconds()} {db_xml} xmlh={len(xml_hosts)} dbh={len(db_hosts)} nxh={len(new_xml_hosts)}')
		for xhost in xml_hosts:
			#newhost = [k for k in xml_hosts if k.ip_address == xhost][0]
			# logger.info(f'[SP] x={xhost} nh={newhost} file={xmlf} xml_hosts={len(xml_hosts)} db_hosts={len(db_hosts)} ipaddr_list={len(ipaddr_list)} new_xml_hosts={len(new_xml_hosts)}')
			if xhost.ip_address in [k.ip_address for k in db_hosts]:
				xhost.refresh_x(db_xml.file_id, scan.scan_id)
				r_count += 1
			else:
				session.add(xhost)
				nh_count += 1
			#db_hosts = session.query(Host).all()
			#logger.debug(f'[sh] xml_hosts={len(xml_hosts)} db_hosts={len(db_hosts)} nhc={nh_count}')
		db_xml.process_time = (datetime.now()-t0).total_seconds()
		session.commit()
		db_hosts_count = session.query(Host).count()
		logger.debug(f'[sh] t:{(datetime.now()-t0).total_seconds()} sending done db_hosts={db_hosts_count} nhc:{nh_count} rc:{r_count}')
		for host in session.query(Host).all():
			hp = db_xml.get_host_ports(host.ip_address)
			for port in hp:
				pname = port.get('name')
				prod = port.get('product')
				proto = port.get('protocol')
				new_port = Port(portnumber=port.get('portid'), first_seen=str(db_xml.scanstart_str), host_id=host.host_id, scan_id=scan.scan_id, file_id=db_xml.file_id, name=pname, product=prod, protocol=proto)
				session.add(new_port)
		session.commit()


def scan_filex(xmlfilename:str, session:sessionmaker):
	nmapxml = XMLFile(xmlfilename)
	scan = Scan(nmapxml.file_id, datetime.now())
	logger.info(f'[sf] nmapxml:{nmapxml} {nmapxml.scandate} scan:{scan}')
	return nmapxml, scan

def scan_xml_file(xmlfilename, session):
	xml_file = XMLFile(xmlfilename)
	session.add(xml_file)
	try:
		session.commit()
	except ProgrammingError as e:
		logger.error(f'[sxf] {e}\n\tDuring commit xml_file = {xml_file} {type(xml_file)}')
		logger.warning(f'xmlfilename={xmlfilename} {type(xmlfilename)}')
		session.rollback()
		return None
	logger.info(f'[sxf] new xmlfile:{xml_file}')
	scan = Scan(xml_file.file_id, datetime.now())
	session.add(scan)
	session.commit()
	hosts = xml_file.get_hosts(scan.scan_id)
	logger.debug(f'[sxf] nmap_xml_id={xml_file.file_id} {xml_file.scandate} scan_id={scan.scan_id} hosts={len(hosts)} ') # dbhosts={session.query(Host).count()}')
	send_hosts_to_db(xml_file, scan, session)


def refresh_db(session):
	all_hosts = session.query(Host).all()
	for host in all_hosts:
		host.refresh_x()
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
	(options, args) = parser.parse_args()
	engine = get_engine('sqlite')
	Session = sessionmaker(bind=engine)
	session = Session()
	db_init(engine)
	if options.xmlfilename and options.xmlpath:
		parser.error("Please specify either a filename or a path, not both")
		return
	elif options.run_nmap:
		print('running nmap')
		n = run_nmap(session)
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
			scan_xml_file(options.xmlfilename, session)
	elif options.xmlpath:
		xmllist = glob.glob(options.xmlpath + '/*.xml')
		scan_path(xmllist, session)
	elif options.refresh_db:
		refresh_db(session)

if __name__ == "__main__":
	main()



