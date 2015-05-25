from twisted.internet.protocol import Factory
from twisted.internet import protocol
from twisted.protocols.policies import TimeoutMixin
from protocol import Protocol
import DataHandler
import Client

class Chat(protocol.Protocol, Client.Client, TimeoutMixin):

	def __init__(self, root):
		self.root = root
		assert(self.root.protocol.userdb)

	def connectionMade(self):
		self.root.session_id += 1
		self.session_id = self.root.session_id
		assert(self.session_id not in self.root.clients)
		self.root.clients[self.session_id] = self
		self.setTimeout(60)
		peer = (self.transport.getPeer().host, self.transport.getPeer().port)
		Client.Client.__init__(self, self.root, peer, self.session_id)
		self.Bind(self.root.protocol)

	def connectionLost(self, reason):
		self.root.protocol._remove(self, reason.value)
		del self.root.clients[self.session_id]

	def dataReceived(self, data):
		if self.username:
			self.resetTimeout()
		self.Handle(data)

	def HandleProtocolCommand(self, cmd):
		## probably caused by trailing newline ("abc\n".split("\n") == ["abc", ""])
		if (len(cmd) < 1):
			return
		self.root.protocol._handle(self, cmd)


	def timeoutConnection(self):
		if self.username:
			self.Send("SERVERMSG timeout: didn't login within 60 seconds")
		else:
			self.Send("SERVERMSG timeout: no data received within 60 seconds")
	        self.transport.loseConnection()

	def Remove(self, reason='Quit'):
		self.transport.loseConnection()

class ChatFactory(Factory):

    def __init__(self, root):
        self.root = root # maps user names to Chat instances
	assert(self.root.userdb != None)

    def buildProtocol(self, addr):
        return Chat(self.root)

