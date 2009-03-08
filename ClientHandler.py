import socket, thread, select, sys, traceback, time, os
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
		self.input = []
		self.output = []
		self.socketmap = {}
		self.clients = []
		self.clients_num = 0
		self.running = False

	def _bind(self):
		self.protocol = Protocol.Protocol(self._root,self)

	def _rebind(self):
		self._bind()
		for client in self.clients:
			#client.Bind(protocol=self.protocol)
			client.Bind(protocol=Protocol.Protocol(self._root,self)) # allows client's protocol to be overridden with ease

	def Run(self):
		# commented out to remove profiling
		if not os.path.isdir('profiling'):
			os.mkdir('profiling')
		thread.start_new_thread(cProfile.runctx,('self.MainLoop()', globals(), locals(), os.path.join('profiling', '%s.log'%(self.num))))
		# normal, no profiling
		#while 1:
		#	try: thread.start_new_thread(self.MainLoop,())
		#	except: self._root.error(traceback.format_exc())
	
	def MainLoop(self):
		self.running = True
		while self.running and self.input:
			try:
				try: inputready,outputready,exceptready = select.select(self.input,self.output,[], 0.5) # should I be using exceptready to close the sockets?
				except:
					for s in self.input:
						try: select.select([s],[],[],0)
						except: self._remove(s)
					continue
				if not self.running: continue
  
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
		self.running = False

	def _remove(self,s):
		if s in self.input:
			self.input.remove(s)
		if s in self.output:
			self.output.remove(s)
		if s in self.socketmap: # called twice sometimes, so needs the check
			client = self.socketmap[s]
			client.Remove()
			try: del self.socketmap[s]
			except: pass

	def AddClient(self, client):
		self.clients_num += 1
		self.socketmap[client.conn] = client
		
		self.clients.append(client)
		client.Bind(self, self.protocol)
		if not self.running: self.Run()

	def RemoveClient(self, client, reason='Quit'):
		self.clients_num -= 1
		if client.conn in self.input:
			self.input.remove(client.conn)
		if client.conn in self.output:
			self.output.remove(client.conn)
		if client in self.clients:
			self.clients.remove(client)
		self._root.console_write('Client disconnected from %s, session ID was %s'%(client.ip_address, client.session_id))
		try: client.conn.close() # >_< limits total users ever connected to ulimit if this is removed. silly me.
		except: pass # already closed
		client._protocol._remove(client, reason)