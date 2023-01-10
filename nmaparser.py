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

VERSION = "0.1.1"
RELEASE_DATE = "2022-09-20"

def main():
	parser = OptionParser(usage="%prog [options] --file xmlfile")
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename", action='store', type='string')
	parser.add_option("-p","--path", dest="xmlpath", help="path to xml files")
	parser.add_option("-d","--drop", dest="droptables", help="drop existing data", action="store", default=False)
	parser.add_option("-c","--check", dest="check", help="check existing data", action="store", default=True)
	parser.add_option("-r","--read", dest="readconfig", help="run scan from config", action="store", type='string')
	(options, args) = parser.parse_args()
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



