#!/usr/bin/python3
#
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
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename")
	parser.add_option("-p","--path", dest="xmlpath", help="path to xml files")
	parser.add_option("-s","--session", dest="sessionname", help="sessionname", default="default")
	parser.add_option("-d","--drop", dest="droptables", help="drop existing data", action="store", default=False)
	parser.add_option("-c","--check", dest="check", help="check existing data", action="store", default=True)
	(options, args) = parser.parse_args()
	if options.droptables:
		drop_tables()
	# Parse nmap file
	if options.xmlfilename:
		scan = nmap.NmapScan(options.xmlfilename)
		print(f"Summary total hosts {len(scan.Hosts)} date:{scan.scanstart_str}")
		print(scan)
		print(options)
		to_database(scan=scan, xmlfile=options.xmlfilename, check=options.check, sessionname=options.sessionname)
	elif options.xmlpath:
		idx = 0
		for xmlfile in glob.glob(options.xmlpath + '/*.xml'):
			scan = nmap.NmapScan(xmlfile)
			print(f"Total hosts {len(scan.Hosts)} date:{scan.scanstart_str} file:{xmlfile} {idx}/{len(glob.glob(options.xmlpath + '/*.xml'))}")
			print(scan)
			print(options)
			to_database(scan=scan, xmlfile=xmlfile, check=options.check, sessionname=options.sessionname)
			idx += 1

if __name__ == "__main__":
	main()



