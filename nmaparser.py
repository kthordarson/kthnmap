#!/usr/bin/python3
#

from loguru import logger
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser

from modules import nmap
from modules.database import to_database

VERSION = "0.1.1"
RELEASE_DATE = "2022-09-20"

def main():
	parser = OptionParser(usage="%prog [options] --file xmlfile")
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename")
	parser.add_option("-d","--drop", dest="droptables", help="drop existing data", action="store", default=False)
	parser.add_option("-c","--check", dest="check", help="check existing data", action="store", default=True)
	(options, args) = parser.parse_args()

	# Parse nmap files
	scan = nmap.NmapScan(options.xmlfilename)
	print(f"Summary total hosts {len(scan.Hosts)} date:{scan.scanstart_str}")
	print(scan)
	print(options)
	to_database(scan=scan, drop=options.droptables, xmlfile=options.xmlfilename, check=options.check)
if __name__ == "__main__":
	main()



