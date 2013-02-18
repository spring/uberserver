import socket, time, sys, thread, ip2country, errno
import Telnet

from collections import defaultdict

class Client:
	'this object represents one connected client'

	def __init__(self, root, connection, address, session_id):
		'initial setup for the connected client'
		self._root = root
		self.conn = connection
		
		# detects if the connection is from this computer
		if address[0].startswith('127.'):
			if root.online_ip:
				address = (root.online_ip, address[1])
			elif root.local_ip:
				address = (root.local_ip, address[1])
		
		self.ip_address = address[0]
		self.local_ip = address[0]
		self.port = address[1]
		
		if root.randomflags:
			self.country_code = ip2country.randomcc()
		else:
			self.setFlagByIP(self.ip_address)
		
		self.session_id = session_id
		self.db_id = session_id
		
		self.handler = None
		self.static = False
		self._protocol = None
		self.removing = False
		self.sendError = False
		self.msg_id = ''
		self.sendbuffer = []
		self.sendingmessage = ''
		self.logged_in = False
		self.status = '12'
		self.cpu = 0
		self.access = 'fresh'
		self.accesslevels = ['fresh','everyone']
		self.channels = []
		
		self.battle_bots = {}
		self.current_battle = None
		self.battle_bans = []
		self.ingame_time = 0
		self.went_ingame = 0
		self.spectator = False
		self.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
		self.teamcolor = '0'
		
		self.username = ''
		self.password = ''
		self.hostport = None
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
		self.reverse_ignore = []
		
		self.tokenized = False
		self.hashpw = False
		self.debug = False
		self.data = ''

		# holds compatibility flags - will be set by Protocol as necessary
		self.compat = defaultdict(lambda: False)
		self.scriptPassword = None
		
		now = time.time()
		self.last_login = now
		self.register_date = now
		self.lastdata = now
		self.last_id = 0
		
		self.users = set([]) # session_id
		self.battles = set([]) # [battle_id] = [user1, user2, user3, etc]
		
		self._root.console_write('Client connected from %s, session ID %s.' % (self.ip_address, session_id))
	
	def setFlagByIP(self, ip, force=True):
		cc = ip2country.lookup(ip)
		if force or cc != '??':
			self.country_code = cc

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
		self.handler.finishRemove(self, reason)

	def Send(self, msg):
		if self.telnet:
			msg = Telnet.filter_out(self,msg)
		
		if not msg: return

		if self.handler.thread == thread.get_ident():
			msg = self.msg_id + msg
			
		self.sendbuffer.append(msg+self.nl)
		self.handler.poller.setoutput(self.conn, True)

	def SendNow(self, msg):
		if self.sendError: return
		if self.telnet:
			msg = Telnet.filter_out(msg)
		if not msg: return
		try:
			self.conn.send(msg+self.nl)
		except socket.error:
			self.sendError = True
			self.Remove()

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
		senddata = self.sendingmessage# [:64] # smaller chunks interpolate better, maybe base this off of number of clients?
		try:
			sent = self.conn.send(senddata)
			self.sendingmessage = self.sendingmessage[sent:] # only removes the number of bytes sent
		except UnicodeDecodeError:
			self.sendingmessage = None
			self._root.console_write('Error sending unicode string, message dropped.')
		except socket.error, e:
			if e == errno.EAGAIN:
				return
			self.Remove()
		
		self.handler.poller.setoutput(self.conn, bool(self.sendbuffer or self.sendingmessage))
	
	# Queuing
	
	def AddUser(self, user):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users: return
		self.users.add(session_id)
		self._protocol.client_AddUser(self, user)
	
	def RemoveUser(self, user):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.users.remove(session_id)
			self._protocol.client_RemoveUser(self, user)
	
	def SendUser(self, user, data):
		if type(user) in (str, unicode):
			try: user = self._root.usernames[user]
			except: return
		session_id = user.session_id
		if session_id in self.users:
			self.Send(data)
	
	def AddBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles: return
		self.battles.add(battle_id)
		self._protocol.client_AddBattle(self, battle)
	
	def RemoveBattle(self, battle):
		battle_id = battle.id
		if battle_id in self.battles:
			self.battles.remove(battle_id)
			self._protocol.client_RemoveBattle(self, battle)
	
	def SendBattle(self, battle, data):
		battle_id = battle.id
		if battle_id in self.battles:
			self.Send(data)
	
	def isAdmin(self):
		return ('admin' in self.accesslevels)
	
	def isMod(self):
		return self.isAdmin() or ('mod' in self.accesslevels) # maybe cache these
