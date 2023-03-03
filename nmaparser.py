#!/usr/bin/python3
# todo create history table for each ip/scan
from loguru import logger
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser
from configparser import ConfigParser
from modules import nmap
from modules.database import xmlscan_to_database, get_engine, drop_tables,scan_to_database
from modules.scanner import do_scan
from modules.nmap import sort_xml_list
from subprocess import Popen, PIPE
from concurrent.futures import (ProcessPoolExecutor, ThreadPoolExecutor, as_completed)
from multiprocessing import cpu_count
from datetime import datetime
MAX_WORKERS = cpu_count()
VERSION = "0.1.2"
RELEASE_DATE = "2023-03-03"
# nmap -iL ~/Documents/samskip/samskipexternal.txt  -oX scanexternal-27022023-01.xml  -sV

def exec_nmap(addr, ports):
	# ports = '179,10001,10029,10074,10117,10147,102,10260,1027,10273,111,11211,1194,123,129,137,139,143,1434,14570,1604,161,16418,16419,16422,16423,16440,16441,1645,16458,16459,16493,16512,16513,16526,16527,16622,16623,16678,16679,16684,16696,16697,16701,16710,16711,16733,16890,16891,16894,16895,16897,16940,16941,16952,16953,16964,16965,16994,16995,16996,16997,17,17006,17007,1701,17034,17035,17036,17037,17050,17051,17068,17069,17071,17078,17139,17166,17167,17185,17194,17195,17201,17258,17259,17300,17318,17350,17356,17357,17384,17424,17425,17462,17463,17520,17521,17583,177,1812,19,1900,19132,20087,21,21025,2123,2152,22,2222,22880,23,2362,2425,24287,25,27015,27016,27036,27105,27841,27960,28015,3,30301,30303,30718,32414,32799,3283,3386,3391,3478,3483,34963,3544,36316,3671,3702,37810,37833,3784,389,4000,4070,41630,41794,427,443,44346,445,44818,4500,465,47808,4800,48899,49239,49334,500,5006,5008,502,50253,5050,50569,5060,5061,5070,5093,5094,5095,514,518,520,523,53413,5349,5351,5353,541,54321,5551,55523,5632,5683,5684,6000,623,626,64626,64738,65379,65476,65486,65496,65499,6881,69,6969,7,7400,784,80,8000,8013,8080,8081,8082,8083,8088,81,853,873,88,8888,9034,9201,9302,9600,981,987'
	# xmlout = f'scan-{addr}-{datetime.now()}.xml'
	portlist = ''.join([k for k in ports])
	xmlout = f'scan-{addr}-{datetime.now()}.xml'.replace(':','').replace(' ','').replace('/','-')
	cmdstr = ['nmap', addr, '-oX', xmlout, '-sV', '-p', portlist]
	out = Popen(cmdstr, stdout=PIPE, stderr=None).communicate()[0]
	res = out.decode('utf-8')
	# logger.info(f'[nmap] {addr} {len(res)} {xmlout} ')
	return xmlout

def run_nmap():
	address_file = 'iplist.txt'
	portlist_file = 'portlist.txt'
	with open(address_file, 'r') as f:
		addr_ = f.readlines()
	addr_list = [k.strip() for k in addr_]
	with open(portlist_file, 'r') as f:
		ports = f.readlines()
	nmapres = []
	with ThreadPoolExecutor(MAX_WORKERS) as executor:
		#futures = [executor.submit(exec_nmap, addr, '-sV -oX -') for addr in addr_list]
		futures = [executor.submit(exec_nmap, addr, ports) for addr in addr_list]
		logger.debug(f'[+] {len(futures)} nmap scans started')
		for future in as_completed(futures):
			xmlfile = future.result()
			scan = nmap.NmapScan(xmlfile)
			logger.info(f'scan {scan} complete xmlfile={xmlfile} sending to db')
			xmlscan_to_database(scan=scan, xmlfile=xmlfile)
	return nmapres

def main():
	parser = OptionParser(usage="%prog [options] --file xmlfile")
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename", action='store', type='string')
	parser.add_option("-p","--path", dest="xmlpath", help="path to xml files")
	parser.add_option("-d","--drop", dest="droptables", help="drop existing data", action="store", default=False)
	parser.add_option("-c","--check", dest="check", help="check existing data", action="store", default=True)
	parser.add_option("-r","--read", dest="readconfig", help="run scan from config", action="store", type='string')
	parser.add_option("--nmap", dest="run_nmap", help="run nmap scan", action="store_true",  default=False)
	(options, args) = parser.parse_args()
	if options.run_nmap:
		print('running nmap')
		n = run_nmap()
	if options.xmlfilename and options.xmlpath:
		parser.error("Please specify either a filename or a path, not both")
		return
	if options.droptables:
		drop_tables()
	# Parse nmap file
	if options.readconfig:
		# todo read config file, run nmap scan, parse results, pass results to parser and send to database
		pass
		# if not os.path.exists(options.readconfig):
		# 	logger.error(f"Config file {options.readconfig} does not exist")
		# 	return
		# else:
		# 	logger.info(f'Running scan from config file {options.readconfig}')
		# 	config = ConfigParser()
		# 	config.read(options.readconfig)
		# 	hosts = [k for k in config.get('targets', 'hosts').split(',')]
		# 	ports = config.get('targets', 'ports')
		# 	opts = config.get('targets', 'options')
		# 	scanconfig=f"{opts} -p{ports}"
		# 	results = []
		# 	for host in hosts:
		# 		print(f'scanning {host} {scanconfig}' )
		# 		res = do_scan(host, scanconfig)
		# 		results.append(res)
		# 	scan_to_database(results)

	if options.xmlfilename:
		scan = nmap.NmapScan(options.xmlfilename)
		logger.info(f"Total hosts {len(scan.Hosts)} date:{scan.scanstart_str}")
		xmlscan_to_database(scan=scan, xmlfile=options.xmlfilename)
	elif options.xmlpath:
		idx = 0
		xmlcount = len(glob.glob(options.xmlpath + '/*.xml'))
		xlist = glob.glob(options.xmlpath + '/*.xml')
		xmllist = sort_xml_list(xlist)
		for xmlfile in xmllist:
			idx += 1
			scan = nmap.NmapScan(xmlfile['filename'])
			logger.info(f"file:{xmlfile['filename'].split('/')[-1]} {idx}/{xmlcount} {xmlcount-idx} total hosts {len(scan.Hosts)} date:{scan.scanstart_str} ")
			xmlscan_to_database(scan=scan, xmlfile=xmlfile['filename'])

if __name__ == "__main__":
	main()



