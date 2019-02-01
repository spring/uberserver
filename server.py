#!/usr/bin/env python3
# coding=utf-8

import _thread as thread

from OpenSSL import SSL

import traceback, signal, socket, sys, logging
from twisted.internet import reactor, ssl
from twisted.internet import task

sys.path.append("protocol")
sys.path.append(".")

from DataHandler import DataHandler
from Client import Client
from NATServer import NATServer

import ip2country # just to make sure it's downloaded
import ChanServ
import twistedserver

_root = DataHandler()
_root.parseArgv(sys.argv)

try:
	signal.SIGHUP

	def sighup(sig, frame):
		logging.info('Received SIGHUP.')
		if _root.sighup:
			_root.reload()

	signal.signal(signal.SIGHUP, sighup)
except AttributeError:
	pass

logging.info('Starting uberserver...')

natport = _root.natport
backlog = 100

try:
	natserver = NATServer(natport)
	thread.start_new_thread(natserver.start,())
	natserver.bind(_root)
except socket.error:
	print('Error: Could not start NAT server - hole punching will be unavailable.')

logging.info('Using %i client handling thread(s).'%_root.max_threads)

_root.init()


try:
	reactor.listenTCP(_root.port, twistedserver.ChatFactory(_root))
	reactor.listenSSL(_root.ssl_port, twistedserver.ChatFactory(_root),
                      ssl.DefaultOpenSSLContextFactory('keys/server.key', 'keys/server.crt'))
	print('Started lobby server!')
	print('Connect the lobby client to')
	print('  public:  %s:%d' %(_root.online_ip, _root.port))
	print('  private: %s:%d' %(_root.local_ip, _root.port))
	reactor.run()

except KeyboardInterrupt:
	logging.info()
	logging.info('Server killed by keyboard interrupt.')
except:
	logging.error(traceback.format_exc())
	logging.info('Deep error, exiting...')

_root.shutdown()

