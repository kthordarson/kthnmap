from sqlalchemy import create_engine, MetaData, Column, Integer, String, DateTime, Date, Boolean, ForeignKey
from sqlalchemy.exc import (ArgumentError, CompileError, DataError, IntegrityError, OperationalError, ProgrammingError)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from IPy import IP

import os
import copy
import ipaddress
from loguru import logger
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from modules.constants import PROTOCOLS, PORT_OPT_COMBINED, PORT_OPT_TCP, PORT_OPT_UDP
#from modules import constants
#from modules import helpers

def sortIpList(ip_list):
    ipl = [(IP(ip).int(), ip) for ip in ip_list]
    ipl.sort()
    return [ip[1] for ip in ipl]


Base = declarative_base()

class NmapSession(Base):
    __tablename__ = 'sessions'
    sessionid = Column(Integer, primary_key=True)
    sessionname = Column(String(255))
    scanid = Column(Integer, ForeignKey('scans.scanid'))
    def __init__(self, sessionname):
        self.sessionname = sessionname

class NmapScan(Base):
    __tablename__ = 'scans'
    scanid = Column(Integer, primary_key=True)
    #Hosts:str = {}
    #Services:str = []
    scandate = Column(String(255))
    scanstart_str = Column(String(255))
    xmlfilename = Column(String(255))
    hostcount = Column(Integer)
    servicecount = Column(Integer)
    sessionname = Column(String(255))
    #Hosts = Column(String(255))
    #Services = Column(String(255))
    # scanargs = Column(String(255))
    def __init__(self, xmlFile):
        # Import xml files
        self.Hosts = {}
        self.Services = []
        self.hostcount = 0
        self.servicecount = 0
        self.xmlfilename = xmlFile
        self.parseNmapXmlFile(xmlFile)


    def __repr__(self):
        return f'nmapoutput: hosts={len(self.Hosts)} services={len(self.Services)}'

    def parseNmapXmlFile(self, nmapXmlFilename):
        count = 0
        # Loop through all nmap xml files
        iMaxStatusLen = 0
        count += 1
        # Try to parse xml and record any failures
        nmap_xml = ""
        try:
            nmap_xml = ET.parse(nmapXmlFilename)
        except Exception as e:
            logger.error(f'{e} failed to import {nmapXmlFilename}')
            return
        # Record that file successfully loaded
        # Find all hosts within xml file
        root = nmap_xml.getroot()
        self.scandate = root.attrib['start']
        self.scanstart_str = root.attrib['startstr']
        # self.scanargs = root.attrib['args']
        for xHost in nmap_xml.findall('.//host'):
            ip = xHost.find("address[@addrtype='ipv4']").get('addr')
            if ip not in self.Hosts:
                self.Hosts[ip] = NmapHost(ip, self.scanid)
                self.hostcount += 1
            curHost = self.Hosts[ip]
            try:
                curHost.hostname = xHost.find('.//hostname').get('name') # hostname will be in nmap xml if PTR (reverse lookup) record present
            except:
                curHost.hostname = ip

            # Store host up status
            curHost.alive = (xHost.find("status").get('state') == 'up')

            # Parse ports
            for xPort in xHost.findall('.//port'):
                # Only parse open ports
                if xPort.find('.//state').get('state') == 'open':
                    self.servicecount += 1
                    curPortId = int(xPort.get('portid'))
                    curProtocol = xPort.get('protocol')
                    curService = ''
                    if(None != xPort.find('.//service')):
                        curService = xPort.find('.//service').get('name')
                        curServiceProduct = xPort.find('.//service').get('product')
                        curServiceExtra = xPort.find('.//service').get('extrainfo')
                        curServiceVersion = xPort.find('.//service').get('version')
                        curServiceostype = xPort.find('.//service').get('ostype')
                    # Store port details
                    curHost.addPort(curProtocol, curPortId, curService, curServiceProduct, curServiceExtra, curServiceVersion, curServiceostype)
                    # Store service details in global variable
                    self.addService(curService, ip, curPortId, curServiceProduct, curServiceExtra, curServiceVersion, curServiceostype)

    # Ger or create new service with host/ip/port details
    def addService(self, svcName, ip, port, product, extra, version, ostype):
        curService = self.getService(svcName, product, extra, version, ostype)
        curServiceHost = self.getServiceHost(curService, ip)
        if port not in curServiceHost.ports:
            curServiceHost.ports.append(port)
        if port not in curService.ports:
            curService.ports.append(port)

    # Get service host or create if necessary
    def getServiceHost(self, service, ip):
        for host in service.hosts:
            if host.ip == ip:
                return host

        newServiceHost = NmapHost(ip, self.scanid)
        service.hosts.append(newServiceHost)
        return newServiceHost

    # Get service or create if necessary
    def getService(self, svcName, product, extra, version, ostype):
        for service in self.Services:
            if service.name == svcName:
                return service #.name, service.product, service.extra, service.version, service.ostype

        newService = NmapService(name=svcName)
        newService.product = product
        newService.extra = extra
        newService.version = version
        newService.ostype = ostype
        self.Services.append(newService)
        # logger.debug(f'[getservice] new service: {newService} total services: {len(self.Services)}')
        return newService

    def getHostDictionary(self, filters=None):
        hostDict = {}
        for host in self.getHosts(filters):
            hostDict[host.ip] = host
        return hostDict

    def getHosts(self):
        matchedHosts = []
        hostIps = sortIpList(self.Hosts)
        for ip in hostIps:
            host = copy.deepcopy(self.Hosts[ip])
            if not host.alive:
                continue
            matched = True
            # Check ports (if at least one filter is set)
            for protocol in PROTOCOLS:
                for port in [port for port in host.ports if port.protocol == protocol]:
                    port.matched = True
                    if port.matched:
                        matched = True

            if matched:
                matchedHosts.append(host)
            else:
                pass
        return matchedHosts

    def getAliveHosts(self, filters=None):
        return [host.ip for host in self.getHosts(filters) if host.alive]

    def getServices(self):
        return self.Services

    def getUniquePortIds(self, protocol=PORT_OPT_COMBINED, hosts=None):
        allPorts = set()
        if(hosts == None):
            hosts = self.getHosts()
        for host in hosts:
            if protocol == PORT_OPT_TCP:
                allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_TCP))
            elif protocol == PORT_OPT_UDP:
                allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_UDP))
            else:
                allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_TCP))
                allPorts = allPorts.union(host.getUniquePortIds(PORT_OPT_UDP))
        return sorted(allPorts)

class NmapService(Base):
    __tablename__ = 'service'
    serviceid = Column(Integer, primary_key=True)
    name = Column(String(255))
    product = Column(String(255))
    extra = Column(String(255))
    version = Column(String(255))
    ostype = Column(String(255))
    scanid = Column(Integer, ForeignKey('scans.scanid'))
    hostid = Column(Integer, ForeignKey('hosts.hostid'))
    def __init__(self,name):#, name, product, extra, version, ostype):
        self.name = name
        self.hosts = []
        self.ports = []

    # def __str__(self):
    #     return f'name={self.name} prod={self.product} extra={self.extra} version={self.version} os={self.ostype}'

    # def __repr__(self):
    #     return f'name={self.name} prod={self.product} extra={self.extra} version={self.version} os={self.ostype}'


class NmapHost(Base):
    __tablename__ = 'hosts'
    hostid = Column(Integer, primary_key=True)
    ip = Column(String(255))
    hostname = Column(String(255))
    alive:bool = Column(Boolean)
    scanid = Column(Integer, ForeignKey('scans.scanid'))
    openports = Column(Integer)
    ports = Column(String(255))
    services = Column(String(255))
    def __init__(self, ip, scanid):
        self.scanid = scanid
        self.ip = ip
        self.ports = []
        self.services = []
        self.matched = True # Used for filtering
        self.filesWithHost = [] # List of nmap files host was found in
        # logger.debug(f'host init scan:{self.scanid} {scanid}')

    # def __str__(self):
    #     return f'ip={self.ip} hostname={self.hostname} alive={self.alive} ports={len(self.ports)}'

    # def __repr__(self):
    #     return f'ip={self.ip} hostname={self.hostname} alive={self.alive} ports={len(self.ports)}'
    def __repr__(self):
        return self.ip
    def getState(self):
        state = "up"
        if not self.alive:
            state = "down"
        return state

    def addPort(self, protocol, portnumber, service, product, extra, version, ostype):
        self.addService(service)
        for port in self.ports:
            if port.portnumber == portnumber and port.protocol == protocol:
                # Port already exists, check if service is blank and add if possible
                if(len(port.service.strip()) == 0):
                    port.service = service
                return
        # Add port if function hasn't already exited
        self.ports.append(NmapPort(protocol, portnumber, service, product, extra, version, ostype))

    def addService(self, service):
        if service not in self.services:
            self.services.append(service)

    def getUniquePortIds(self,protocol='',port_filter=[], service_filter=[]):
        allPortIds = []
        for port in self.ports:
            if(len(port_filter) > 0 and port.portnumber not in port_filter):
                continue
            if(len(service_filter) > 0 and port.service not in service_filter):
                continue
            if len(protocol) == 0 or port.protocol == protocol:
                allPortIds.append(port.portnumber)

        uniquePortIds = set(allPortIds)
        return sorted(uniquePortIds)

    def getHostname(self):
        if self.hostname == self.ip:
            return ''
        return self.hostname

class NmapPort(Base):
    __tablename__ = 'ports'
    portid = Column(Integer, primary_key=True)
    portnumber = Column(Integer)
    protocol = Column(String(255))
    service = Column(String(255))
    prodcut = Column(String(255))
    extra = Column(String(255))
    version = Column(String(255))
    ostype = Column(String(255))
    scanid = Column(Integer, ForeignKey('scans.scanid'))
    hostid = Column(Integer, ForeignKey('hosts.hostid'))
    def __init__(self, protocol, port, service, product, extra, version, ostype):
        self.protocol = protocol
        self.portnumber = port
        self.service = service
        self.prodcut = product
        self.extra = extra
        self.version = version
        self.ostype = ostype
        self.matched = True # Used for filtering

    def __str__(self) -> str:
        return f'proto={self.protocol} portnumber={self.portnumber} service={self.service} prod={self.prodcut} extra={self.extra} version={self.version} ostype={self.ostype}'

    def __repr__(self) -> str:
        return f'proto={self.protocol} portnumber={self.portnumber} service={self.service} prod={self.prodcut} extra={self.extra} version={self.version} ostype={self.ostype}'

