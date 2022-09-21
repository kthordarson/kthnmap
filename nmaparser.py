#!/usr/bin/python3
#
# Script to help extract useful information from one or more nmap files
# Also provides interactive prompt with filtering
#
# Created By: Jonathon Orr
# Email: scripts@jonathonorr.co.uk
from loguru import logger
import os, glob, sys, re, subprocess
import xml.etree.ElementTree as ET
from optparse import OptionParser

from modules import nmap
from modules.database import to_database

VERSION = "0.1.1"
RELEASE_DATE = "2022-09-20"

def main():
	parser = OptionParser(usage="%prog [options] [list of nmap xml files or directories containing xml files]")
	parser.add_option("-p", "--port", dest="ports", help="Optional port filter argument e.g. 80 or 80,443", metavar="PORTS")
	parser.add_option("--service", dest="svcFilter", help="Optional service filter argument e.g. http or ntp,http (only used in conjunction with -s)")
	parser.add_option("-e","--exec", dest="cmd", help="Script or tool to run on each IP remaining after port filter is applied. IP will be appended to end of script command line", metavar="CMD")
	parser.add_option("-l","--iplist", dest="ipList", action="store_true", help="Print plain list of matching IPs")
	parser.add_option("-a","--alive-hosts", dest="aliveHosts", action="store_true", help="Print plain list of all alive IPs")
	parser.add_option("-s","--service-list", dest="servicelist", action="store_true", help="Also print list of unique services with names")
	parser.add_option("-S","--host-summary", dest="hostSummary", action="store_true", help="Show summary of scanned/alive hosts")
	parser.add_option("-v","--verbose", dest="verbose", action="store_true", help="Verbose service list")
	parser.add_option("-u", "--unique-ports", dest="uniquePorts", action="store_true", default=False, help="Print list of unique open ports")
	parser.add_option("-R","--raw", dest="raw", action="store_true", help="Only print raw output (no headers)")
	parser.add_option("-r","--recurse", dest="recurse", action="store_true", help="Recurse subdirectories if directory provided for nmap files")
	parser.add_option("-c","--combine", dest="combine", help="Combine all input files into single nmap-parse compatible xml file")
	parser.add_option("--imported-files", dest="importedFiles", action="store_true", help="List successfully imported files")
	parser.add_option("-V","--version", dest="version", action="store_true", help="Print version info")
	parser.add_option("-f","--filename", dest="xmlfilename", help="xmlfilename")
	(options, args) = parser.parse_args()

	if(options.version):
		print("kNmap Parser Version %s\nReleased: %s" % (VERSION,RELEASE_DATE))
		return

	# Parse nmap files
	scan = nmap.NmapScan(options.xmlfilename)
	print(f"Summary total hosts {len(scan.Hosts)} date:{scan.scanstart_str}")
	print(scan)
	# hosts=scan.getHosts()
	# for host in hosts:
	# 	if len(host.ports) != 0:
	# 		print(f'host {host}')
	# print(scan.getServices())
	to_database(scan)
if __name__ == "__main__":
	main()



