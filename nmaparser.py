#!/usr/bin/python3
# todo create history table for each ip/scan
from loguru import logger
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser

from modules import nmap
from modules.database import to_database, get_engine, drop_tables

VERSION = "0.1.1"
RELEASE_DATE = "2022-09-20"

def main():
	parser = OptionParser(usage="%prog [options] --file xmlfile")
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename", action='store', type='string')
	parser.add_option("-p","--path", dest="xmlpath", help="path to xml files")
	parser.add_option("-s","--session", dest="sessionname", help="sessionname", default="default")
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
	elif options.readconfig:
		# todo read config file, run nmap scan, parse results, pass results to parser and send to database
		pass
	elif options.xmlfilename:
		scan = nmap.NmapScan(options.xmlfilename)
		logger.info(f"Total hosts {len(scan.Hosts)} date:{scan.scanstart_str}")
		to_database(scan=scan, xmlfile=options.xmlfilename, sessionname=options.sessionname)
	elif options.xmlpath:
		idx = 0
		xmlcount = len(glob.glob(options.xmlpath + '/*.xml'))
		for xmlfile in glob.glob(options.xmlpath + '/*.xml'):
			idx += 1
			scan = nmap.NmapScan(xmlfile)
			logger.info(f"file:{xmlfile} {idx}/{xmlcount} {xmlcount-idx} total hosts {len(scan.Hosts)} date:{scan.scanstart_str} ")
			to_database(scan=scan, xmlfile=xmlfile, sessionname=options.sessionname)

if __name__ == "__main__":
	main()



