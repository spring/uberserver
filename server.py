#!/usr/bin/env python
# coding=utf-8

try:
	import thread
except:
	# thread was renamed to _thread in python 3
	import _thread

import traceback, signal, socket, sys
from twisted.internet import reactor

sys.path.append("protocol")
sys.path.append(".")

from DataHandler import DataHandler
from Client import Client
from NATServer import NATServer
from XmlRpcServer import XmlRpcServer

import ip2country # just to make sure it's downloaded
import ChanServ
import twistedserver

# uncomment for debugging deadlocks, creates a stacktrace at the given interval to stdout
#import stacktracer
#stacktracer.trace_start("trace.html",interval=5,auto=True) # Set auto flag to always update file!


_root = DataHandler()
_root.parseArgv(sys.argv)

try:
	signal.SIGHUP
	
	def sighup(sig, frame):
		_root.console_write('Received SIGHUP.')
		if _root.sighup:
			_root.reload()

	signal.signal(signal.SIGHUP, sighup)
except AttributeError:
	pass

_root.console_write('-'*40)
_root.console_write('Starting uberserver...\n')

natport = _root.natport
backlog = 100

try:
	natserver = NATServer(natport)
	try:
		thread.start_new_thread(natserver.start,())
	except NameError:
		_thread.start_new_thread(natserver.start,())
	natserver.bind(_root)
except socket.error:
	print('Error: Could not start NAT server - hole punching will be unavailable.')

_root.console_write('Using %i client handling thread(s).'%_root.max_threads)

try:
	xmlrpcserver = XmlRpcServer(_root, _root.xmlhost, _root.xmlport)
	try:
		thread.start_new_thread(xmlrpcserver.start,())
	except NameError:
		_thread.start_new_thread(xmlrpcserver.start,())
	_root.console_write('Listening for XMLRPC clients on %s:%d' % (_root.xmlhost, _root.xmlport))
except socket.error:
	print('Error: Could not start XmlRpcServer.')

_root.init()

try:
	reactor.listenTCP(_root.port, twistedserver.ChatFactory(_root))
	print('Started lobby server!')
	print('Connect the lobby client to')
	print('  public:  %s:%d' %(_root.online_ip, _root.port))
	print('  private: %s:%d' %(_root.local_ip, _root.port))
	reactor.run()

except KeyboardInterrupt:
	_root.console_write()
	_root.console_write('Server killed by keyboard interrupt.')
except:
	_root.error(traceback.format_exc())
	_root.console_write('Deep error, exiting...')

_root.shutdown()

memdebug = False
if memdebug:
	recursion = []
	names = {}
	
	def dump(obj, tabs=''):
		if obj in recursion: return str(obj)
		else: recursion.append(obj)
		try:
			if type(obj) == (list, set):
				return [dump(var) for var in obj]
			elif type(obj) in (str, unicode, int, float):
				return obj
			elif type(obj) == dict:
				output = {}
				for key in obj:
					output[key] = dump(obj[key], tabs+'\t')
			else:
				output = {}
				ovars = vars(obj)
				for key in ovars:
					if key in names: names[key] += 1
					else: names[key] = 1
					output[key] = dump(ovars[key], tabs+'\t')
			return '\n'.join(['%s%s:\n%s\t%s' % (tabs, key, tabs, output[key]) for key in output]) if output else {}
		except: return 'no __dict__'
	
	print('Dumping memleak info.')
	f = open('dump.txt', 'w')
	f.write(dump(_root))
	f.close()
	
	counts = {}
	for name in names:
		count = names[name]
		if count in counts:
			counts[count].append(name)
		else:
			counts[count] = [name]
	
	f = open('counts.txt', 'w')
	for key in reversed(sorted(counts)):
		f.write('%s: %s\n' % (key, counts[key]))
	f.close()
