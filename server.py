#!/usr/bin/env python
# coding=utf-8
import thread, socket, time, sys, traceback
from urllib import urlopen
from ClientHandler import ClientHandler
from DataHandler import DataHandler
from Client import Client
from NATServer import NATServer
import ip2country

_root = DataHandler()
_root.parseArgv(sys.argv)

print
print 'Detecting local IP:',
local_addr = socket.gethostbyname(socket.gethostname())
print local_addr

print 'Detecting online IP:',
try:
	# web_addr = urlopen('http://www.zjt3.com/ip.php').read() # site down
	web_addr = urlopen('http://whatismyip.com/automation/n09230945.asp').read()
	print web_addr
except:
	web_addr = local_addr
	print 'not online'
print

host = ''
port = _root.port
natport = _root.port
backlog = 100
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR,
                               server.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) | 1 ) # we can restart uberserver and it will ignore TIME_WAIT :D
server.bind((host,port))
server.listen(backlog)
input = [server]

_root.local_ip = local_addr
_root.online_ip = web_addr

_root.LAN = True

natserver = NATServer(natport)
thread.start_new_thread(natserver.start,())
natserver.bind(_root)

curthread = 0
maxthreads = 25
for iter in range(maxthreads):
	_root.clienthandlers.append( ClientHandler(_root, iter) )

print 'uberserver starting on port %i'%port
print 'Using %i client handling thread(s).'%maxthreads

running = 1
clients = {}

def AddClient(client):
	# start detection of handler with the least clients
	curthread = 0
	lowlen = -1
	for iter in range(len(_root.clienthandlers)):
		curtest = _root.clienthandlers[iter].clients_num
		if curtest < lowlen or lowlen == -1:
			lowlen = curtest
			curthread = iter
			if lowlen == 0:
				break # end if it's at 0, we won't get much lower :>
	# end detection -- this code places a new client in the handler with the least clients
	if not _root.clienthandlers[iter].running:
		thread.start_new_thread(_root.clienthandlers[iter].Run, ())
	_root.clienthandlers[curthread].AddClient(client)
	clients[client] = curthread

def RemoveClient(client):
	threadnum = clients[client]
	_root.clienthandlers[threadnum].RemoveClient(client)

#try:
#        import Users
#except:
#        exit() # replace with a working fallback to lan mode

try:
	while running:
		connection, address = server.accept()
		if address[0].startswith('127.'): # detects if the connection is from this computer
			if web_addr:
				address = (web_addr, address[1])
			elif local_addr:
				address = (local_addr, address[1])
		country_code = ip2country.lookup(address[0]) # actual flag
		#country_code = ip2country.randomcc() # random flags
		client = Client(_root, connection, address, _root.session_id, country_code)
		_root.clients[_root.session_id] = client
		AddClient(client)
		_root.session_id += 1
		#time.sleep(0.05) # just in case... # not sure what sleeping after connect is good for? remove it?
except KeyboardInterrupt:
	print
	print 'Server killed by keyboard interrupt.'
except:
	print '-'*60
	traceback.print_exc(file=sys.stdout)
	print '-'*60
	print 'Deep error, exiting...'
print 'Killing handlers.'
for handler in _root.clienthandlers:
	handler.running = False	
print 'Killing clients.'
for client in dict(_root.clients):
	_root.clients[client].conn.close()
server.close()
