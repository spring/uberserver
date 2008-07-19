class ChanServ:
	def __init__(self, client, root):
		self.client = client
		self._root = root
	
	def onLogin(self):
		self.client.status = self.client._protocol._calc_status(self.client, 0)
		self.Send('JOIN main')
	
	def Handle(self, msg):
		if msg.count(' '):
			cmd, args = msg.split(' ', 1)
			if cmd == 'SAID':
				self.handleSAID( args )
			if cmd == 'SAIDPRIVATE':
				self.handleSAIDPRIVATE( args )
	
	def handleSAID(self, msg):
		chan, user, msg = msg.split(' ',2)
		if msg.startswith('!'):
			msg = msg.lstrip('!')
			if msg.lower() == 'help':
				help = self.Help(user)
				hlist = []
				for s in help.split('\n'):
					hlist.append('SAYPRIVATE %s %s' % (user, s) )
				self.Send( hlist )
			else:
				self.Send('SAYPRIVATE %s %s' % ( user, self.HandleCommand(chan, user, msg) ))
	
	def handleSAIDPRIVATE(self, msg):
		user, msg = msg.split(' ', 1)
		if msg.startswith('!'):
			msg = msg.lstrip('!')
			if msg.lower() == 'help':
				help = self.Help(user)
				hlist = []
				for s in help.split('\n'):
					hlist.append('SAYPRIVATE %s %s' % (user, s) )
				self.Send( hlist )
			else:
				if msg.count(' ') >= 2:
					cmd, chan, msg = msg.split(' ',2)
					chan = chan.lstrip('#')
					self.Send('SAYPRIVATE %s %s' % ( user, self.HandleCommand(chan, user, cmd, args=msg) ))
				elif msg.count(' '):
					cmd, chan = msg.split(' ',1)
					chan = chan.lstrip('#')
					self.Send('SAYPRIVATE %s %s' % ( user, self.HandleCommand(chan, user, msg) ))
					
				else:
					self.Send('SAYPRIVATE %s Error: Invalid params.' % user)
	
	def Help(self, user):
		return 'Hello, %s!\nI am an automated channel service bot,\nfor the full list of commands, see http://taspring.clan-sy.com/dl/ChanServCommands.html\nIf you want to go ahead and register a new channel, please contact one of the server moderators!' % user
	
	def HandleCommand(self, chan, user, cmd, args=None):
		cmd = cmd.lower()
		print chan, user, cmd, args
		if cmd == 'info':
			return 'channel info'
		if cmd == 'topic':
			if not args:
				return 'topic disabled'
			else:
				return 'topic is now %s' % topic
		if cmd == 'register':
			if 'mod' in self._root.usernames[user].accesslevels:
				if not args: args = user
				return 'Channel #%s successfully registered to <%s>' % ( chan, args.split(' ',1)[0] )
			else:
				return 'Sorry, you must contact one of the server moderators to register a channel for you.'
		return ''

	
	def Send(self, msg):
		if type(msg) == list or type(msg) == tuple:
			for s in msg:
				self.client._protocol._handle( self.client, s )
		elif type(msg) == str:
			if '\n' in msg:
				for s in msg.split('\n'):
					self.client._protocol._handle( self.client, s )
			else:
				self.client._protocol._handle( self.client, msg )

class Client:
	'this object is chanserv implemented through the standard client interface'

	def __init__(self, root, address, session_id, country_code):
		'initial setup for the connected client'
		self.ChanServ = ChanServ(self, root)
		self.static = True # can't be removed... don't want to anyway :)
		self._protocol = False
		self.removing = False
		self.msg_id = ''
		self.sendingmessage = ''
		self._root = root
		self.ip_address = address[0]
		self.local_ip = address[0]
		self.logged_in = True
		self.port = address[1]
		self.conn = False
		self.country_code = country_code
		self.session_id = session_id
		self.status = '12'
		self.access = 'admin'
		self.accesslevels = ['admin', 'mod', 'user', 'everyone']
		self.channels = []
		self.username = ''
		self.password = ''
		self.hostport = 8542
		self.blind_channels = []
		
		self._root.console_write( 'ChanServ connected from %s, session ID %s.' % (self.ip_address, session_id) )
		
		self.ingame_time = 0
		self.bot = 1
		self.username = 'ChanServ'
		self.password = 'ChanServ'
		self.cpu = '9001'
		self.local_ip = None
		self.hook = ''
		self.went_ingame = 0
		self.local_ip = self.ip_address
		self.lobby_id = 'ChanServ'
		self._root.usernames[self.username] = self
		self._root.console_write('Successfully logged in static user <%s> on session %s.'%(self.username, self.session_id))
		

	def Bind(self, handler=None, protocol=None):
		if handler:
			self.handler = handler
		if protocol:
			self._protocol = protocol
			self.ChanServ.onLogin()

	def Handle(self, data):
		pass

	def Remove(self):
		pass

	def Send(self, msg):
		self.SendNow(msg)

	def SendNow(self, msg):
		if not msg: return
		self.ChanServ.Handle(msg)

	def FlushBuffer(self):
		pass
