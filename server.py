#!/usr/bin/env python
# coding=utf-8

import thread, socket, time, sys, traceback
from urllib import urlopen
from DataHandler import DataHandler
from Client import Client
from NATServer import NATServer
from Dispatcher import Dispatcher
import ip2country # just to make sure it's downloaded
import ChanServ

_root = DataHandler()
_root.parseArgv(sys.argv)

_root.console_write('-'*40)
_root.console_write('Starting uberserver...\n')

host = ''
port = _root.port
natport = _root.natport
backlog = 100
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR,
				server.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) | 1 )
				# fixes TIME_WAIT :D
server.bind((host,port))
server.listen(backlog)

try:
	natserver = NATServer(natport)
	thread.start_new_thread(natserver.start,())
	natserver.bind(_root)
except socket.error:
	print 'Error: Could not start NAT server - hole punching will be unavailable.'

_root.console_write()
_root.console_write('Detecting local IP:')
try: local_addr = socket.gethostbyname(socket.gethostname())
except: local_addr = '127.0.0.1'
_root.console_write(local_addr)

_root.console_write('Detecting online IP:')
try:
	web_addr = urlopen('http://whatismyip.com/automation/n09230945.asp').read()
	_root.console_write(web_addr)
except:
	web_addr = local_addr
	_root.console_write('not online')
_root.console_write()

_root.local_ip = local_addr
_root.online_ip = web_addr

_root.console_write('Listening for clients on port %i'%port)
_root.console_write('Using %i client handling thread(s).'%_root.max_threads)

dispatcher = Dispatcher(_root, server)

chanserv = True
if chanserv:
	address = ((web_addr or local_addr), 0)
	chanserv = ChanServ.ChanServClient(_root, address, _root.session_id)
	dispatcher.addClient(chanserv)

try:
	dispatcher.pump()
except KeyboardInterrupt:
	_root.console_write()
	_root.console_write('Server killed by keyboard interrupt.')
except:
	_root.error(traceback.format_exc())
	_root.console_write('Deep error, exiting...')

_root.console_write('Killing handlers.')
for handler in _root.clienthandlers:
	handler.running = False
_root.console_write('Killing clients.')
for client in dict(_root.clients):
	try:
		conn = _root.clients[client].conn
		if conn: conn.close()
	except: pass # for good measure
server.close()

while _root.console_buffer: time.sleep(0.5)
time.sleep(5)

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
	
	print 'Dumping memleak info.'
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