import random
random.seed()

try:
	from ip2c.ip2country import ip2country
	ip2c = ip2country()
	working = True
except IOError:
	working = False
	print 'IP2Country database initialization failed. Try running the update function.'
	print
except ImportError:
	working = False
	print 'ip2c module not found. IP2Country lookups not available.'
	print

def lookup(ip):
	if not working:
		return '??'
	index = ip2c.lookup(ip)
	if index == -1:
      		cc = '??'
	elif index == -2: # no ip specified
		cc = '??'
		print 'No IP specified'
	elif index == -3: # invalid ip2country database
		print 'IP2Country database failure.'
		cc = '??'
	else:
		cc = ip2c.countryCode(index)
	return cc

def randomcc():
	if not working:
		return '??'
	cclen = len(ip2c.countryname)
	return ip2c.countryCode( random.randint(2, cclen)-1 )

def update():
	import urllib, zipfile, sys, os
	from ip2c import makedb
	
	url = 'http://ip-to-country.webhosting.info/downloads/ip-to-country.csv.zip'
	isGeo = False
	
	print
	print 'Downloading IP2Country database from \n[%s]\n'%url
	urlfile = urllib.urlopen(url)
	
	length = int(urlfile.info()['content-length'])
	
	inc_bytes = True
	total_bytes = 0
	linestatus = 50
	print 'Length: %s bytes'%length
	iteration = -1
	bytes = ''
	
	while inc_bytes:
		inc_bytes = urlfile.read(1024)
		if inc_bytes:
			bytes += inc_bytes
		total_bytes += len(inc_bytes)
		linestatus += 1
		if linestatus == 51:
			iteration += 1
			if iteration > 0:
				sys.stdout.write(' [%s]'%(('%i%%'%(total_bytes*100/length)).rjust(4)))
			print '\n'+('%iK -> '%(iteration*50)).rjust(10),
			linestatus = 1
		if linestatus % 10 == 1 and linestatus > 1:
			print ' ',
		if bytes:
			sys.stdout.write('.')
		#print '.',
	
	just = 50 - linestatus + 5 - (linestatus / 10)
	sys.stdout.write((' [%s]'%(('%i%%'%(total_bytes*100/length)).rjust(4))).rjust(just+6))
	
	print
	print
	
	print 'Download complete: %s/%s'%(total_bytes, length)
	print
	
	temp = open('ip-to-country.csv.zip', 'wb')
	temp.write(bytes)
	temp.close()
	
	zipdb = zipfile.ZipFile('ip-to-country.csv.zip', 'r')
	csvfile = open('ip-to-country.csv', 'w')
	csvfile.write(zipdb.read(zipdb.namelist()[0]))
	zipdb.close()
	
	csvfile.close()
	
	
	print 'Making database...'
	makedb.readFile('ip-to-country.csv', isGeo)
	
	print '\nCleaning up..'
	os.remove('ip-to-country.csv.zip')
	os.remove('ip-to-country.csv')
	
	print '\nDone.'
