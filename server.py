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

