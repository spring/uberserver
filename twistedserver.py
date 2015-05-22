#!/usr/bin/env python
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor
from protocol import Protocol
import DataHandler
import Client

class Chat(LineReceiver, Client.Client):

	def __init__(self, root):
		self.root = root
		self.users = {}
		assert(self.root.protocol.userdb)

	def connectionMade(self):
		self.root.sessions += 1
		peer = (self.transport.getPeer().host, self.transport.getPeer().port)
		super(Chat, self).__init__( self.root, None, peer, self.root.sessions)
		self.root.protocol._new(self)

	def connectionLost(self, reason):
		self.root.protocol._remove(self, reason)

	#def lineReceived(self, line):
	#	print line
	#	self.root.protocol._handle(self, line)

	def dataReceived(self, data):
		data = data.strip("\n")
		print "Received: '%s'" %(data)
		for line in data.split("\n"):
			if line.strip():
				self.root.protocol._handle(self, line)

	def Send(self, msg):
		print "Sending: '%s'" %(msg)
		self.transport.write(msg.encode("utf-8")+"\n")

	def FlushBuffer(self): #noop
		pass

	def set_msg_id(self, msg):
		self.msg_id = ""

		if (not msg.startswith('#')):
			return msg

		test = msg.split(' ')[0][1:]

		if (not test.isdigit()):
			return msg

		self.msg_id = '#%s ' % test
		return (' '.join(msg.split(' ')[1:]))
	def Remove(self, reason): #Client overrides
		pass

class ChatFactory(Factory):

    def __init__(self):
        self.root = DataHandler.DataHandler() # maps user names to Chat instances
	self.root.init()
	self.root.protocol = Protocol.Protocol(self.root)
	self.root.sessions = 0
	print "test"
	assert(self.root.userdb != None)

    def buildProtocol(self, addr):
        return Chat(self.root)


reactor.listenTCP(8200, ChatFactory())
reactor.run()

