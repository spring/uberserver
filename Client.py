import socket, time, sys, thread
import Telnet


class Client:
	'this object represents one connected client'

	def __init__(self, root, connection, address, session_id, country_code):
		'initial setup for the connected client'
		self._root = root
		self.conn = connection
		self.ip_address = address[0]
		self.local_ip = address[0]
		self.port = address[1]
		self.country_code = country_code
		self.session_id = session_id
		self.db_id = session_id
		
		self.handler = None
		self.static = False
		self._protocol = None
		self.removing = False
		self.msg_id = ''
		self.sendbuffer = []
		self.sendingmessage = ''
		self.logged_in = False
		self.status = '12'
		self.access = 'fresh'
		self.accesslevels = ['fresh','everyone']
		self.channels = []
		self.battle_bots = {}
		self.current_battle = None
		self.battle_bans = []
		self.username = ''
		self.password = ''
		self.ingame_time = 0
		self.hostport = 8452
		self.udpport = 0
		self.bot = 0
		self.hook = ''
		self.floodlimit = {'fresh':{'msglength':1024, 'bytespersecond':1024, 'seconds':2},
							'user':{'msglength':1024, 'bytespersecond':1024, 'seconds':10},
							'bot':{'msglength':1024, 'bytespersecond':10240, 'seconds':5},
							'mod':{'msglength':10240, 'bytespersecond':10240, 'seconds':10},
							'admin':{'disabled':True},}
		self.msglengthhistory = {}
		self.lastsaid = {}
		self.nl = '\n'
		self.telnet = False
		self.current_channel = ''
		self.blind_channels = []
		self.tokenized = False
		self.hashpw = False
		self.debug = False
		self.data = ''
		
		now = time.time()
		self.last_login = now
		self.register_date = now
		self.lastdata = now
		
		self.users = [] # session_id
		self.userqueue = {} # [session_id] = [{'type': ['message', 'remove'], 'data':['CLIENTSTATUS', '']}, etc]
		self.battles = {} # [battle_id] = [user1, user2, user3, etc]
		self.battlequeue = {} # [battle_id] = [{'type': ['message', 'remove'], 'data':['CLIENTBATTLESTATUS', '']}, etc]
		
		self._root.console_write('Client connected from %s, session ID %s.' % (self.ip_address, session_id))

	def Bind(self, handler=None, protocol=None):
		if handler:	self.handler = handler
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
				self.Remove('Kicked for flooding')
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
			self.conn.close()
		except socket.error: #socket shut down by itself ;) probably got a bad file descriptor
			try: self.conn.close()
			except socket.error: pass # in case shutdown was called but not close.
		self.handler.RemoveClient(self, reason)

	def Send(self, msg):
		if self.telnet:
			msg = Telnet.filter_out(self,msg)
		if not msg: return
		if self.handler.thread == thread.get_ident():
			self.sendbuffer.append(self.msg_id+'%s%s' % (msg, self.nl))
		else:
			self.sendbuffer.append('%s%s' % (msg, self.nl))
		self.handler.poller.setoutput(self.conn)
#		cflocals = sys._getframe(2).f_locals    # this whole thing with cflocals is basically a complicated way of checking if this client
#		if 'self' in cflocals:                  # was called by its own handling thread, because other ones won't deal with its msg_id
#			if 'handler' in dir(cflocals['self']):
#				if cflocals['self'].handler == self.handler:
#					self.sendbuffer.append(self.msg_id+'%s%s'%(msg,self.nl))
#					handled = True
#		if not handled:
#			self.sendbuffer.append('%s%s'%(msg,self.nl))

	def SendNow(self, msg):
		if self.telnet:
			msg = Telnet.filter_out(msg)
		if not msg: return
		try:
			self.conn.send(msg+self.nl)
		except socket.error: self.handler._remove(self.conn)

	def FlushBuffer(self):
		if self.data and self.telnet: # don't send if the person is typing :)
			return
		if not self.sendingmessage:
			message = ''
			while not message:
				if not self.sendbuffer: # just in case, since it returns before going to the end...
					self.handler.poller.setoutput(self.conn, False)
					return
				message = self.sendbuffer.pop(0)
			self.sendingmessage = message
		senddata = self.sendingmessage[:64] # smaller chunks interpolate better, maybe base this off of number of clients?
		try:
			sent = self.conn.send(senddata)
			self.sendingmessage = self.sendingmessage[sent:] # only removes the number of bytes sent
		except socket.error: self.handler._remove(self.conn)
		
		if not self.sendbuffer:
			self.handler.poller.setoutput(self.conn, False)
	
	# Queuing
	
	def AddUser(self, user):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users: return
		self.users.append(session_id)
		self._protocol.client_AddUser(self, user)
		if session_id in self.userqueue:
			while self.userqueue[session_id]:
				item = self.userqueue[session_id].pop(0)
				if item['type'] == 'remove':
					del self.userqueue[session_id]
					break
				elif item['type'] == 'message':
					self.Send(item['data'])
	
	def RemoveUser(self, user):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.users.remove(session_id)
			if session_id in self.userqueue:
				del self.userqueue[session_id]
			self._protocol.client_RemoveUser(self, user)
		else:
			self.userqueue[session_id] = [{'type':'remove'}]
	
	def SendUser(self, user, data):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.Send(data)
		else:
			if not session_id in self.userqueue:
				self.userqueue[session_id] = []
			self.userqueue[session_id].append({'type':'message', 'data':data})
	
	
	def AddBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles: return
		self.battles[battle_id] = []
		self._protocol.client_AddBattle(self, battle)
		if battle_id in self.battlequeue:
			while self.battlequeue[battle_id]:
				item = self.battlequeue[battle_id].pop(0)
				if item['type'] == 'remove':
					del self.battlequeue[battle_id]
					break
				elif item['type'] == 'message':
					self.Send(item['data'])
	
	def RemoveBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles:
			del self.battles[battle_id]
			if battle_id in self.battlequeue:
				del self.battlequeue[battle_id]
			self._protocol.client_RemoveBattle(self, battle)
		else:
			self.battlequeue[battle_id] = [{'type':'remove'}]
	
	def SendBattle(self, battle, data):
		battle_id = battle.id
		if battle_id in self.battles:
			self.Send(data)
		else:
			if not battle_id in self.battlequeue:
				self.battlequeue[battle_id] = []
			self.battlequeue[battle_id].append({'type':'message', 'data':data})
	
	def userMatch(self, matchObj):
		if type(matchObj) in (unicode, str):
			return matchObj == self.username
		elif type(matchObj) in (int, float):
			return abs(self.db_id - matchObj) < 0.001
		elif type(matchObj) == list:
			return (self.db_id in list) or (self.username in list)