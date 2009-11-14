import socket, thread, Multiplexer, sys, traceback, time, os
import cProfile # for profiling
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
		self.poller = Multiplexer.BestMultiplexer() # best available multiplexer - priority from best to worst: kqueue, epoll, poll, select
		self.socketmap = {}
		self.clients = []
		self.clients_num = 0
		self.thread = 0
		self.running = False

	def _bind(self):
		self.protocol = Protocol.Protocol(self._root,self)

	def _rebind(self):
		self._bind()
		for client in self.clients:
			#client.Bind(protocol=self.protocol)
			client.Bind(protocol=Protocol.Protocol(self._root,self)) # allows client's protocol to be overridden with ease

	def Run(self):
		if self.running: return
		self.running = True
		profiling = True
		if profiling:
			if not os.path.isdir('profiling'):
				os.mkdir('profiling')
			thread.start_new_thread(cProfile.runctx,('self.MainLoop()', globals(), locals(), os.path.join('profiling', '%s.log'%(self.num))))
		else:
			thread.start_new_thread(self.MainLoop,())
	
	def MainLoop(self):
		self.thread = thread.get_ident()
		try:
			self._root.console_write('Handler %s: Starting.'%self.num)
			while self.running and not self.poller.empty():
				try:
					inputs, outputs, errors = self.poller.poll()
					#time.sleep(0.01)
					if not self.running: continue

					for s in inputs:
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

					for s in outputs:
						try:
							self.socketmap[s].FlushBuffer()
						except KeyError:
							self._remove(s)
						except socket.error:
							s.close()
							self._remove(s)
				except:	self._root.error(traceback.format_exc())
			self.running = False
			self._root.console_write('Handler %s: Stopping.'%self.num)
		except:
			self._root.error(traceback.format_exc())

	def _remove(self, s):
		self.poller.unregister(s)
		if s in self.socketmap:
			client = self.socketmap[s]
			client.Remove()
			self._removeSocket(s)
	
	def _removeSocket(self, s):
		try: del self.socketmap[s]
		except KeyError: pass

	def AddClient(self, client):
		self.clients_num += 1
		
		self.clients.append(client)
		client.Bind(self, self.protocol) # if we bind second, a ton of cpu load can cause a self.handler exception in the client
		
		if not client.static: # static clients don't have a socket
			self.socketmap[client.conn] = client
			self.poller.register(client.conn)
		
		if not self.running: self.Run()

	def RemoveClient(self, client, reason='Quit'):
		if client.static: return # static clients don't disconnect
		self.clients_num -= 1
		s = client.conn
		self.poller.unregister(s)
		self._removeSocket(s)
		if client in self.clients:
			self.clients.remove(client)
		self._root.console_write('Client disconnected from %s, session ID was %s'%(client.ip_address, client.session_id))
		client._protocol._remove(client, reason)