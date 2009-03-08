import socket, time, sys
import Telnet


class Client:
	'this object represents one connected client'
	handler = None
	static = False
	_protocol = None
	removing = False
	msg_id = ''
	sendbuffer = []
	sendingmessage = ''
	logged_in = False
	status = '12'
	access = 'fresh'
	accesslevels = ['fresh','everyone']
	channels = []
	battle_bots = {}
	current_battle = None
	battle_bans = []
	username = ''
	password = ''
	ingame_time = 0
	hostport = 8452
	udpport = 0
	bot = 0
	hook = ''
	floodlimit = {'fresh':{'msglength':1024, 'bytespersecond':1024, 'seconds':2},
						'user':{'msglength':1024, 'bytespersecond':1024, 'seconds':10},
						'bot':{'msglength':1024, 'bytespersecond':10240, 'seconds':5},
						'mod':{'msglength':10240, 'bytespersecond':10240, 'seconds':10},
						'admin':{'disabled':True},}
	msglengthhistory = {}
	lastsaid = {}
	nl = '\n'
	telnet = False
	current_channel = ''
	blind_channels = []
	tokenized = False
	hashpw = False
	debug = False
	data = ''

	def __init__(self, root, connection, address, session_id, country_code):
		'initial setup for the connected client'
		self._root = root
		self.conn = connection
		self.ip_address = address[0]
		self.local_ip = address[0]
		self.port = address[1]
		self.country_code = country_code
		self.session_id = session_id
		
		_root.console_write('Client connected from %s, session ID %s.' % (self.ip_address, session_id))
		now = time.time()
		self.last_login = now
		self.register_date = now
		self.lastdata = now

	def Bind(self, handler=None, protocol=None):
		if handler:
			self.handler = handler
			if not self.conn in self.handler.input:
				self.handler.input.append(self.conn)
			if len(self.sendbuffer)>0:
				if not self.conn in self.handler.output:
					self.handler.output.append(self.conn)
		if protocol:
			if not self._protocol:
				protocol._new(self)
			self._protocol = protocol

	def Handle(self, data):
		if self.bot and not (self.access in self.floodlimit and 'disabled' in self.floodlimit[self.access]): limit = self.floodlimit['bot']
		elif self.access in self.floodlimit: limit = self.floodlimit[self.access]
		else: limit = self.floodlimit['user']
		if not 'disabled' in limit:
			msglength = limit['msglength']
			bytespersecond = limit['bytespersecond']
			seconds = limit['seconds']
			now = int(time.time())
			self.lastdata = now
			if now in self.msglengthhistory:
				self.msglengthhistory[now] += len(data)
			else:
				self.msglengthhistory[now] = len(data)
			total = 0
			for iter in dict(self.msglengthhistory):
				if iter < now - (seconds-1):
					del self.msglengthhistory[iter]
				else:
					total += self.msglengthhistory[iter]
			if total > (bytespersecond * seconds):
				self.SendNow('SERVERMSG No flooding (over %s per second for %s seconds)'%(bytespersecond, seconds))
				self._protocol._remove(self, 'Kicked for flooding')
				self.Remove()
				return
		self.data += data
		if self.data.count('\n') > 0:
			data = self.data.split('\n')
			(datas, self.data) = (data[:len(data)-1], data[len(data)-1:][0])
			for data in datas:
				if data.endswith('\r') and self.telnet: # causes fail on TASClient, so only enable on telnet
					self.nl = '\r\n'
				command = data.rstrip('\r').lstrip(' ') # strips leading spaces and trailing carriage return
				if not 'disabled' in limit and len(command) > msglength:
					self.Send('SERVERMSG Max length exceeded (%s): no message for you.'%msglength)
				else:
					if self.telnet:
						command = Telnet.filter_in(self,command)
					if type(command) == str:
						command = [command]
					for cmd in command:
						self._protocol._handle(self,cmd)

	def Remove(self, reason='Quit'):
		try:
			self.conn.shutdown(socket.SHUT_RDWR)
		except socket.error: #socket shut down by itself ;) probably got a bad file descriptor
			pass
		self.handler.RemoveClient(self, reason)

	def Send(self, msg):
		if self.telnet:
			msg = Telnet.filter_out(self,msg)
		if not msg: return
		handled = False
		cflocals = sys._getframe(2).f_locals    # this whole thing with cflocals is basically a complicated way of checking if this client
		if 'self' in cflocals:                  # was called by its own handling thread, because other ones won't deal with its msg_id
			if hasattr(cflocals['self'], 'handler'):
				if cflocals['self'].handler == self.handler:
					self.sendbuffer.append(self.msg_id+'%s%s'%(msg,self.nl))
					handled = True
		if not handled:
			self.sendbuffer.append('%s%s'%(msg,self.nl))
		if len(self.sendbuffer)>0 and self.handler:
			if not self.conn in self.handler.output:
				self.handler.output.append(self.conn)

	def SendNow(self, msg):
		if self.telnet:
			msg = Telnet.filter_out(msg)
		if not msg: return
		try:
			self.conn.send(msg+self.nl)
		except socket.error:
			if self.conn in self.handler.output:
				self.handler._remove(self.conn)

	def FlushBuffer(self):
		if self.data and self.telnet: # don't send if the person is typing :)
			return
		if not self.sendingmessage:
			message = ''
			while not message:
				if not self.sendbuffer: return
				message = self.sendbuffer.pop(0)
			self.sendingmessage = message
		senddata = self.sendingmessage[:64] # smaller chunks interpolate better, maybe base this off of number of clients?
		try:
			sent = self.conn.send(senddata)
			self.sendingmessage = self.sendingmessage[sent:] # only removes the number of bytes sent
		except socket.error:
			if self.conn in self.handler.output:
				self.handler._remove(self.conn)
		if len(self.sendbuffer) == 0 and not self.sendingmessage:
			if self.conn in self.handler.output:
				self.handler.output.remove(self.conn)
