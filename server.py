#!/usr/bin/env python
# coding=utf-8

import thread, socket, time, sys, traceback
from urllib import urlopen
from ClientHandler import ClientHandler
from DataHandler import DataHandler
from Client import Client
from NATServer import NATServer
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

natserver = NATServer(natport)
thread.start_new_thread(natserver.start,())
natserver.bind(_root)

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

running = 1

def AddClient(client):
	# start detection of handler with the least clients
	curthread = 0
	lowlen = -1
	# allows for on-the-fly increasing of threads
	if _root.max_threads > len(_root.clienthandlers):
		i = len(_root.clienthandlers)
		_root.clienthandlers.append( ClientHandler(_root, i) )
		curthread = i
	else:
		for i in range(len(_root.clienthandlers)):
			curtest = _root.clienthandlers[i].clients_num
			if curtest < lowlen or lowlen == -1:
				lowlen = curtest
				curthread = i
				if lowlen == 0:
					break # end if it's at 0, we won't get much lower :>
	# end detection -- this code places a new client in the handler with the least clients
	_root.clienthandlers[curthread].AddClient(client) # if we add the client before running the loop, we don't need to wait or do pending clients :/

try:
	if web_addr:
		address = (web_addr, 0)
	elif local_addr:
		address = (local_addr, 0)
	chanserv = ChanServ.ChanServClient(_root, address, _root.session_id)
	_root.clients[_root.session_id] = chanserv
	AddClient(chanserv)
	_root.session_id += 1
	while running:
		try: connection, address = server.accept()
		except socket.error, e:
			if e[0] == 24: # ulimit maxfiles
				_root.console_write('Maximum files reached, refused new connection.')
			else:
				raise socket.error, e
		if address[0].startswith('127.'): # detects if the connection is from this computer
			if web_addr:
				address = (web_addr, address[1])
			elif local_addr:
				address = (local_addr, address[1])
		
		client = Client(_root, connection, address, _root.session_id)
		_root.clients[_root.session_id] = client
		AddClient(client)
		_root.session_id += 1
		#if not _root.session_id % (_root.max_threads*2):
		#	time.sleep(0.1)
		#time.sleep(0.05) # just in case... # not sure what sleeping after connect is good for? remove it? # maybe decreases load on database.
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