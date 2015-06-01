#!/usr/bin/python

import GeoIP

dbfile = "/usr/share/GeoIP/GeoIP.dat"

def loaddb():
	global geoip
	try:
		geoip = GeoIP.open(dbfile, GeoIP.GEOIP_STANDARD)
		return True
	except Exception as e:
		print("Couldn't load %s: %s" % (dbfile, str(e)))
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
	print(lookup("37.187.59.77"))
	print(lookup("77.64.139.108"))
	print(lookup("78.46.100.157"))
	print(lookup("8.8.8.8"))
	print(lookup("0.0.0.0"))
