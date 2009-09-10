import socket, thread, select, sys, traceback, time, os
if 'poll' in dir(select):
	from select import POLLIN, POLLPRI, POLLOUT, POLLERR, POLLHUP, POLLNVAL
import cProfile # for profiling
from Client import Client
# from Protocol import Protocol
# from Protocol import Protocol_034 as Protocol # legacy support
import Protocol

class PollMultiplexer:
	def __init__(self):
		self.poller = select.poll()
	def register(self, fd):
		if not fd in self.sockets: self.sockets[fd.fileno()] = fd
		return self.poller.register(fd)
	def unregister(self, fd):
		if fd in self.sockets: del self.sockets[fd]
		return self.poller.unregister(fd)
		
	def setoutput(self, fd): return
		
	def poll(self):
		results = self.poller.poll(0.1)
		inputs = outputs = errors = []
		for fd, mask in results:
			if mask & POLLIN == POLLIN or mask & POLLPRI == POLLPRI: inputs.append(self.sockets[fd])
			if mask & POLLOUT == POLLOUT: outputs.append(self.sockets[fd])
			if mask & POLLERR == POLLERR or mask & POLLHUP == POLLHUP or mask & POLLNVAL == POLLNVAL: errors.append(self.sockets[fd])
		return inputs, outputs, errors
	def empty(self):
		if not self.sockets: return True

class SelectMultiplexer:
	def __init__(self):
		self.sockets = set([])
		self.output = set([])
	def register(self, fd):
		self.sockets.add(fd)
		
	def unregister(self, fd):
		if fd in self.sockets:
			self.sockets.remove(fd)
			if fd in self.output:
				self.output.remove(fd)
		
	def setoutput(self, fd, ready):
		# this if structure means it only scans output once.
		if not ready and fd in self.output:
			self.output.remove(fd)
		elif ready:
			self.output.add(fd)
			
	def poll(self):
		if not self.sockets: return ([], [] ,[])
		try: return select.select(self.sockets, self.output, [], 0.1)
		except select.error:
			inputs = outputs = errors = []
			for s in self.sockets:
				try: select.select([s], [s], [], 0.01)
				except:
					errors.append(s)
					self.unregister(s)
			inputs, outputs, _ = select.select(self.sockets, self.output, [], 0.1)
			return inputs, outputs, errors
	def empty(self):
		if not self.sockets: return True

class ClientHandler:
	'''This represents one client handler. Threading is recommended. Multiple copies work.'''
	def __init__(self, root, num):
		self.num = num
		self._root = root
		self._bind()
		if 'poll' in dir(select) and False: self.poller = PollMultiplexer()
		else: self.poller = SelectMultiplexer()
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
		# commented out to remove profiling
		#if not os.path.isdir('profiling'):
		#	os.mkdir('profiling')
		#thread.start_new_thread(cProfile.runctx,('self.MainLoop()', globals(), locals(), os.path.join('profiling', '%s.log'%(self.num))))
		# normal, no profiling
		thread.start_new_thread(self.MainLoop,())
	
	def MainLoop(self):
		self.thread = thread.get_ident()
		try:
			self._root.console_write('Handler %s: Starting.'%self.num)
			while self.running and not self.poller.empty():
				try:
					#try: inputready,outputready,exceptready = select.select(list(self.input),list(self.output),[], 0.5) # should I be using exceptready to close the sockets?
					#except: continue
					inputs, outputs, errors = self.poller.poll()
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
		except: self._root.error(traceback.format_exc())

	def _remove(self, s):
		self.poller.unregister(s)
		if s in self.socketmap:
			client = self.socketmap[s]
			client.Remove()
			self._removeSocket(s)
	
	def _removeSocket(self, s):
		try: self.socketmap.remove(s)
		except: pass

	def AddClient(self, client):
		self.clients_num += 1
		if not client.static: # static clients don't have a socket
			self.socketmap[client.conn] = client
			self.poller.register(client.conn)
		
		self.clients.append(client)
		client.Bind(self, self.protocol)
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