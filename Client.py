import socket, time, sys
#from Protocol import Protocol_034 as Protocol
from Protocol import Protocol

class Client:
	'this object represents one connected client'

	def __init__(self, root, handler, connection, address, session_id, country_code):
		'initial setup for the connected client'
		self.msg_id = ''
		self.sendbuffer = ''
		self.handler = handler
		self.conn = connection
		self.ip_address = address[0]
		self.logged_in = False
		self.port = address[1]
		self.country_code = country_code
		self.session_id = session_id
		self._protocol = Protocol(root,handler)
		self._root = root
		self.status = '12'
		self.username = ''
		self.password = ''
		print 'Client connected from %s, session ID %s.' % (self.ip_address, session_id)
		self.data = ''
		self._protocol._new(self)

	def Handle(self, data):
		self.data += data
		if self.data.count('\n') > 0:
                        data = self.data.split('\n')
                        (datas, self.data) = (data[:len(data)-1], data[len(data)-1:][0])
                        for data in datas:
                                command = data.rstrip('\r').lstrip(' ') # strips leading spaces and trailing carriage return
                                self._protocol._handle(self,command)

	def Remove(self):
                self._protocol._remove(self)

	def Send(self,msg):
                handled = False
                cflocals = sys._getframe(2).f_locals    # this whole thing with cflocals is basically a complicated way of checking if this client
                if 'self' in cflocals:                  # was called by its own handling thread, because other ones won't deal with its msg_id
                        if hasattr(cflocals['self'], 'handler'):
                                if cflocals['self'].handler == self.handler:
                                        self.sendbuffer += self.msg_id+'%s\n'%msg
                                        handled = True
                if not handled:
                        self.sendbuffer += '%s\n'%msg
		if len(self.sendbuffer.strip('\n'))>0:
                        if not self.conn in self.handler.output:
                                self.handler.output.append(self.conn)

	def FlushBuffer(self):
		senddata = self.sendbuffer[:512] # smaller chunks interpolate better, maybe base this off of number of clients?
		sent = self.conn.send(senddata)
		self.sendbuffer = self.sendbuffer[sent:] # only removes the number of bytes sent
		if len(self.sendbuffer) == 0:
                        if self.conn in self.handler.output:
                                self.handler.output.remove(self.conn)
