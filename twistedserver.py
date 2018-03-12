from twisted.internet.protocol import Factory
from twisted.internet import protocol
from twisted.protocols.policies import TimeoutMixin
from protocol import Protocol
import DataHandler
import Client
import traceback
import logging
import resource

maxhandles, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
maxclients = int(maxhandles / 2)

class Chat(protocol.Protocol, Client.Client, TimeoutMixin):

	def __init__(self, root):
		self.root = root
		assert(self.root.protocol.userdb)

	def connectionMade(self):
		try:
			clientcount = len(self.root.clients)
			if clientcount >= maxclients:
				logging.error("to many connections: %d > %d" %(clientcount, maxclients))
				self.transport.write(b"DENIED to many connections, sorry!\n")
				self.transport.abortConnection()
				return

			self.root.session_id += 1
			self.session_id = self.root.session_id
			assert(self.session_id not in self.root.clients)
			self.root.clients[self.session_id] = self
			self.setTimeout(60)
			peer = (self.transport.getPeer().host, self.transport.getPeer().port)
			Client.Client.__init__(self, self.root, peer, self.session_id)
			self.root.protocol._new(self)
		except Exception as e:
			logging.error("Error in adding client: %s %s %s" %(str(e), self.transport.getPeer().host, str(traceback.format_exc())))

	def connectionLost(self, reason):
		if not hasattr(self, 'session_id'): #not probably connected
			return
		self.root.protocol._remove(self, str(reason.value))
		del self.root.clients[self.session_id]

	def dataReceived(self, data):
		try:
			if self.username:
				self.resetTimeout() #reset timeout for authentificated users when data is received
			self.Handle(data.decode("utf-8"))
		except Exception as e:
			logging.error("Error in handling data from client: %s %s, %s, %s" % (self.username, str(e), data, str(traceback.format_exc())))

	def timeoutConnection(self):
		self.transport.abortConnection()

	def Remove(self, reason='Quit'):
		self.transport.loseConnection()

	def StartTLS(self):
		try:
			self.transport.startTLS(self.root.cert)
		except Exception as e:
			logging.error("Error in handling data from client: %s, %s" % (str(e), str(traceback.format_exc())))
			self.transport.abortConnection()

class ChatFactory(Factory):

	def __init__(self, root):
		self.root = root # maps user names to Chat instances
		assert(self.root.userdb != None)

	def buildProtocol(self, addr):
		return Chat(self.root)

