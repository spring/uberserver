#!/usr/bin/env python
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from protocol import Protocol
import DataHandler
import Client

class Chat(LineReceiver, Client.Client):

	def __init__(self, root):
		self.root = root
		assert(self.root.protocol.userdb)

	def connectionMade(self):
		self.root.session_id += 1
		self.session_id = self.root.session_id
		self.root.clients[self.session_id] = self
		peer = (self.transport.getPeer().host, self.transport.getPeer().port)
		super(Chat, self).__init__( self.root, None, peer, self.session_id)
		self.Bind(None, self.root.protocol)

	def connectionLost(self, reason):
		self.root.protocol._remove(self, reason)
		del self.root.clients[self.session_id]

	def dataReceived(self, data):
		self.Handle(data)

	def Send(self, msg):
		self.transport.write(msg.encode("utf-8")+"\n")

	def FlushBuffer(self): #Client overrides
		pass

	def Remove(self, reason):
		pass

class ChatFactory(Factory):

    def __init__(self, root):
        self.root = root # maps user names to Chat instances
	assert(self.root.userdb != None)

    def buildProtocol(self, addr):
        return Chat(self.root)

