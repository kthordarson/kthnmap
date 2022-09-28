from libnmap.parser import NmapParser, NmapParserException
from libnmap.process import NmapProcess
from configparser import ConfigParser

def do_scan(targets, options):
	parsed = None
	nmproc = NmapProcess(targets, options)
	rc = nmproc.run()
	if rc != 0:
		print('Nmap scan failed: {0}'.format(nmproc.stderr))
	try:
		parsed = NmapParser.parse(nmproc.stdout)
	except NmapParserException as e:
		print('Exception raised while parsing scan: {0}'.format(e.msg))
	return parsed

def main():
	config = ConfigParser()
	config.read('config.ini')
	hosts = [k for k in config.get('targets', 'hosts').split(',')]
	ports = config.get('targets', 'ports')
	opts = config.get('targets', 'options')
	scanconfig=f"{opts} -p{ports}"
	results = []
	for host in hosts:
		print(f'scanning {host} {scanconfig}' )
		res = do_scan(host, scanconfig)
		results.append(res)
	print(results)

if __name__ == '__main__':
	main()
