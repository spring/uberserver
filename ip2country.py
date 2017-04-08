#!/usr/bin/python3
# coding=utf-8
# This file is part of the uberserver (GPL v2 or later), see LICENSE

dbfile = "/usr/share/GeoIP/GeoIP.dat"

def loaddb():
	global geoip
	try:
		import GeoIP
		geoip = GeoIP.open(dbfile, GeoIP.GEOIP_STANDARD)
		return True
	except Exception as e:
		print("Couldn't load %s: %s" % (dbfile, str(e)))
		print("Hint: apt-get install geoip-database python-geoip")
		return False

working = loaddb()

def lookup(ip):
	if not working: return '??'
	addrinfo = geoip.country_code_by_addr(ip)
	if not addrinfo: return '??'
	return addrinfo

def reloaddb():
	working = loaddb()


if __name__ == '__main__':
	assert(lookup("37.187.59.77")  == 'FR')
	assert(lookup("77.64.139.108") == 'DE')
	assert(lookup("78.46.100.157") == 'DE')
	assert(lookup("8.8.8.8")       == 'US')
	assert(lookup("0.0.0.0")       == '??')
	print("Test ok!")
