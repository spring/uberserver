import socket, thread, select, sys, traceback, time, os
#import cProfile # for profiling
from Client import Client
# from Protocol import Protocol
# from Protocol import Protocol_034 as Protocol # legacy support
import Protocol

class ClientHandler:
	'''This represents one client handler. Threading is recommended. Multiple copies work.'''
	def __init__(self, root, num):
		self.num = num
		self._root = root
		self._bind()
		self.input = []
		self.output = []
		self.socketmap = {}
		self.pending_clients = {}
		self.clients = {}
		self.clients_num = 0
		self.running = False

	def _bind(self):
		self.protocol = Protocol.Protocol(self._root,self)

	def _rebind(self):
		reload(sys.modules['SayHooks'])
		reload(sys.modules['Protocol'])
#		reload(sys.modules['SQLUsers']) # later
		self._bind()
		for client in self.clients:
			client.Bind(protocol=self.protocol)

	def Run(self):
		# commented out to remove profiling
		#if not os.path.isdir('profiling'):
		#	os.mkdir('profiling')
		#cProfile.runctx('self.MainLoop()', globals(), locals(), os.path.join('profiling', '%s_%s.log'%(int(time.time()),self.num)))
		# normal, no profiling
		while 1:
			self.running = True
			try: self.MainLoop()
			except: self._root.error(traceback.format_exc())
	
	def MainLoop(self):
		while self.running:
			while not self.input and not self.pending_clients and self.running:
				time.sleep(0.1)
			for client in dict(self.pending_clients):
				try:
					if not client in self.clients and client in self.pending_clients:
						self.clients[client] = ''
						client.Bind(self, self.protocol)
					del self.pending_clients[client]
					break # hax to only handle one each time around :)
				except:	self._root.error(traceback.format_exc())
			while self.input or self.pending_clients:
				try:
					for client in dict(self.pending_clients):
						try:
							if not client in self.clients and client in self.pending_clients:
								self.clients[client] = ''
								client.Bind(self, self.protocol)
							del self.pending_clients[client]
							break # hax to only handle one each time around :)
						except:	self._root.error(traceback.format_exc())
					if not self.input:
						continue
   
					try:
						inputready,outputready,exceptready = select.select(self.input,self.output,[], 0.5)
					except:
						inputready = []
						outputready = []
   
					for s in inputready:
						try:
							data = s.recv(1024)
						except socket.error:
							self._remove(s)
							continue
						if data:
							if s in self.socketmap:
								self.socketmap[s].Handle(data)
						else:
							self._remove(s)
   
					for s in outputready:
						try:
							self.socketmap[s].FlushBuffer()
						except KeyError:
							self._remove(s)
						except socket.error:
							s.close()
							self._remove(s)
				except:	self._root.error(traceback.format_exc())

	def _remove(self,s):
		if s in self.input:
			self.input.remove(s)
		if s in self.output:
			self.output.remove(s)
		if s in self.socketmap: # for some reason gets called twice sometimes, so needs the check
			client = self.socketmap[s]
			client.Remove()
			try: del self.socketmap[s]
			except: pass

	def AddClient(self, client):
		self.clients_num += 1
		self.pending_clients[client] = ''
		self.socketmap[client.conn] = client

	def RemoveClient(self, client):
		self.clients_num -= 1
		if client.conn in self.input:
			self.input.remove(client.conn)
		if client in self.clients:
			del self.clients[client]
		self._root.console_write('Client disconnected from %s, session ID was %s'%(client.ip_address, client.session_id))
		#if client.username in self._root.usernames:
		#    del self._root.usernames[client.username]
		client._protocol._remove(client)
		#del self._root.clients[client.session_id]
