import time

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
				self.handleSAID(args)
			if cmd == 'SAIDPRIVATE':
				self.handleSAIDPRIVATE(args)
				
	def handleSAID(self, msg):
		chan, user, msg = msg.split(' ',2)
		if msg.startswith('!'):
			msg = msg.lstrip('!')
			if msg.lower() == 'help':
				help = self.Help(user)
				hlist = []
				for s in help.split('\n'):
					hlist.append('SAYPRIVATE %s %s' % (user, s))
				self.Send(hlist)
			else:
				if msg.count(' ') >= 2:
					cmd, chan, args = msg.split(' ',2)
					chan = chan.lstrip('#')
				#if msg.startswith('#'): # wtf was I thinking
				#	if msg.count(' '):
				#		chan, msg = msg.lstrip('#').split(' ')
				#		if msg.count(' '): msg = msg.split(' ',1)[0]
				#		msg = user
				#	else:
				#		chan = msg.lstrip('#')
				#		msg = user
				self.Send('SAYPRIVATE %s %s' % (user, self.HandleCommand(chan, user, msg)))
	
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
				response = ''
				if msg.count(' ') >= 2:
					cmd, chan, msg = msg.split(' ',2)
					chan = chan.lstrip('#')
					response = self.HandleCommand(chan, user, cmd, msg)
				elif msg.count(' '):
					cmd, chan = msg.split(' ',1)
					chan = chan.lstrip('#')
					msg = user
					reponse = self.HandleCommand(chan, user, msg)
				else:
					response = 'Error: Invalid params'
				if response: self.Send('SAYPRIVATE %s %s' % (user, response))
	
	def Help(self, user):
		return 'Hello, %s!\nI am an automated channel service bot,\nfor the full list of commands, see http://taspring.clan-sy.com/dl/ChanServCommands.html\nIf you want to go ahead and register a new channel, please contact one of the server moderators!' % user
	
	def HandleCommand(self, chan, user, cmd, args=None):
		print chan, user, cmd, args
		client = self._root.usernames[user]
		if 'mod' in client.accesslevels:
			access = 'mod'
		elif user == self._root.channels[chan]['owner']:
			access = 'founder'
		elif user in self._root.channels[chan]['admins']:
			access = 'op'
		else:
			access = 'normal'
		cmd = cmd.lower()
		
		if cmd == 'info':
			channel = self._root.channels[chan]
			founder = channel['founder']
			if founder: founder = 'Founder is <%s>'
			else: founder = 'No founder is registered'
			admins = channel['admins']
			users = channel['users']
			antispam = channel['antispam']['enabled']
			if not admins: mods = 'no operators are registered'
			else: mods = '%i registered operators are %s' % (len(admins), ', '.join(admins))
			if len(users) == 1: users = '1 user'
			else: users = '%i users' % len(users)
			return '%#s info: Anti-spam protection is %s. <%s>, %s. %s currently in the channel.' % (chan, antispam, founder, mods, users)
		if cmd == 'topic':
			if not args:
				self._root.channels[chan]['topic'] = None
				self._root.broadcast('CHANNELMESSAGE %s Topic disabled.')
				return '%#s: Topic disabled' % chan
			else:
				topicdict = {'user':client.username, 'text':args, 'time':'%s'%(int(time.time())*1000)}
				self._root.broadcast('CHANNELMESSAGE %s Topic changed.')
				self._root.broadcast('CHANNELTOPIC %s %s %s %s'%(chan, user, topicdict['time'], topicdict['text']), chan)
				return '%#s: Topic changed' % topic
		if cmd == 'register':
			print 'register', access, args
			if access == 'mod':
				if not args: args = user
				self._root.channels[chan]['founder'] = args
				self.Send('JOIN %s' % chan)
				self._root.broadcast('CHANNELMESSAGE %s Channel has been registered to <%s>' % (chan, args))
				return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])
			else:
				return '#%s: You must contact one of the server moderators or the owner of the channel to register a channel' % chan
		if cmd == 'unregister':
			if access in ['mod', 'founder']:
				self._root.channels[chan]['founder'] = ''
				self._root.broadcast('CHANNELMESSAGE %s Channel has been unregistered' % chan)
				self.client.Send('LEAVE %s' % chan)
				return '#%s: Successfully unregistered.' % chan
			else:
				return '#%s: You must contact one of the server moderators or the owner of the channel to unregister a channel' % chan
		if cmd == 'changefounder':
			if access in ['mod', 'founder']:
				if not args: return '#%s: You must specify a new founder' % chan
				self._root.channels[chan]['founder'] = args
				self._root.broadcast('CHANNELMESSAGE %s Founder has been changed to <%s>' % (chan, args))
				return '#%s: Successfully changed founder to <%s>' % (chan, args)
			else:
				return '#%s: You must contact one of the server moderators or the owner of the channel to change the founder' % chan
		if cmd == 'spamprotection':
			if access in ['mod', 'founder']:
				antispam = self._root.channels[chan]['antispam']
				if antispam['quiet']: antispam['quiet'] = 'on'
				else: antispam['quiet'] = 'off'
				status = 'on (settings: timeout:%(timeout)i, quiet:%(quiet)s, aggressiveness:%(aggressiveness)i, bonuslength:%(bonuslength)i, duration:%(duration)i)' % antispam
				if args == 'on':
					self._root.channels[chan]['antispam']['enabled'] = True
					antispam = self._root.channels[chan]['antispam']
					self._root.broadcast('CHANNELMESSAGE %s Anti-spam protection was enabled by <%s>' % (chan, args, user))
					return '#%s: Anti-spam protection is %s' % (chan, status)
				elif args == 'off':
					self._root.channels[chan]['antispam']['enabled'] = False
					self._root.broadcast('CHANNELMESSAGE %s Anti-spam protection was disabled by <%s>' % (chan, args, user))
					return '#%s: Anti-spam protection is off' % chan
			if not antispam['enabled']: status = 'off'
			return '#%s: Anti-spam protection is %s' % (chan, status)
		if cmd == 'spamsettings':
			if access in ['mod', 'founder']:
				antispam = self._root.channels[chan]['antispam']
				spaces = args.count(' ')
				if spaces == 4:
					timeout, quiet, aggressiveness, bonuslength, duration = args.split(' ')
					if ('%i%i%i%i' % (timeout, aggressiveness, bonuslength, duration)).isdigit() and quiet in ('on', 'off'):
						self._root.channels[chan]['antispam'].update({'timeout':int(timeout), 'aggressiveness':int(aggressiveness), 'bonuslength':int(bonuslength), 'duration':int(duration), 'quiet':(quiet=='on')})
				return '#%s: Error: Invalid args for spamsettings. Valid syntax is "!spamsettings <timeout> <quiet> <agressiveness> <bonuslength> <duration>". All args but quiet are integers, which is "on" or "off".' % chan
		if cmd == 'op':
			if access in ['mod', 'founder']:
				if not args: return '#%s: You must specify a user to op' % chan
				if args in self._root.channels[chan]['admins']: return '#%s: <%s> was already an op' % (chan, args)
				self._root.channels[chan]['admins'].append(args)
				self._root.broadcast('CHANNELMESSAGE %s <%s> added to the operator list by <%s>' % (chan, args, user), chan)
				return '#%s: <%s> added to the operator list' % (chan, args)
			else:
				return '#%s: You do not have permission to op users' % chan
		if cmd == 'deop':
			if access in ['mod', 'founder']:
				if not args: return '#%s: You must specify a user to deop' % chan
				if not args in eslf._root.channels[chan]['admins']: return '#%s: <%s> was not an op' % (chan, args)
				self._root.channels[chan]['admins'].remove(args)
				self._root.broadcast('CHANNELMESSAGE %s <%s> removed from the operator list by <%s>' % (chan, args, user), chan)
				return '#%s: <%s> removed from the operator list' % (chan, args)
			else:
				return '#%s: You do not have permission to deop users' % chan
		if cmd == 'chanmsg':
			if access in ['mod', 'founder', 'op']:
				if not args: return '#%s: You must specify a channel message' % chan
				if access == 'op': args = 'issued by <%s>: %s' % (user, args)
				self._root.broadcast('CHANNELMESSAGE %s %s' % (chan, args), chan)
				return #return '#%s: insert chanmsg here'
			else:
				return '#%s: You do not have permission to issue a channel message' % chan
		if cmd == 'lock':
			if access in ['mod', 'founder', 'op']:
				if not args: return '#%s: You must specify a channel key to lock a channel' % chan
				self._root.channels[chan]['key'] = args
				self._root.broadcast('CHANNELMESSAGE %s Channel locked by <%s>' % user, chan)
				return '#%s: Locked'
			else:
				return '#%s: You do not have permission to lock the channel' % chan
		if cmd == 'unlock':
			if access in ['mod', 'founder', 'op']:
				self._root.channels[chan]['key'] = None
				self._root.broadcast('CHANNELMESSAGE %s Channel unlocked by <%s>' % (chan, user), chan)
				return '#%s: Unlocked' % chan
			else:
				return '#%s: You do not have permission to unlock the channel' % chan
		if cmd == 'kick':
			if access in ['mod', 'founder', 'op']:
				if not args: return '#%s: You must specify a user to kick from the channel' % chan
				if args in self._root.channels[chan]['users']:
					self._root.broadcast('CHANNELMESSAGE %s <%s> kicked from the channel by <%s>' % (chan, msg, arg, user), chan)
					self._root.channels[channel]['users'].remove(username)
					self._root.broadcast('LEFT %s %s kicked from channel.'%(chan, args), chan)
				else: return '#%s: <%s> not in channel' % (chan, args)
				return '#%s: <%s> kicked' % (chan, user)
			else:
				return '#%s: You do not have permission to kick users from the channel' % chan
		if cmd == 'mute':
			if access in ['mod', 'founder', 'op']:
				if not args: return '#%s: You must specify a user to mute' % chan
				try:
					duration = float(duration)*60
					if duration < 1:
						duration = -1
					else:
						duration = time.time() + duration
				except ValueError: duration = -1
				self._root.channels[chan]['mutelist'][user] = duration
				if not user in self._root.channels[chan]['mutelist']:
					if duration > 0: duration = 'for (%i) seconds' % duration
					else: duration = 'forever'
					self._root.broadcast('CHANNELMESSAGE %s <%s> has muted <%s> %s'%(chan, user, args, duration), chan)
					return '#%s: <%s> muted for (%i) seconds' % (chan, args)
				else:
					return '#%s: <%s> muted for (%i) seconds' % (chan, args)
			else:
				return '#%s: You do not have permission to mute users' % chan
		if cmd == 'unmute':
			if access in ['mod', 'founder', 'op']:
				if not args: return '#%s: You must specify a user to unmute' % chan
				if args in self._root.channels[chan]['mutelist']:
					self._root.broadcast('CHANNELMESSAGE %s <%s> has unmuted <%s>' % (chan, user, args), chan)
					return '#%s: <%s> unmuted' % (chan, args)
				else: return '#%s: <%s> is not muted' % (chan, args)
			else:
				return '#%s: You do not have permission to unmute users' % chan
		if cmd == 'mutelist':
			if True:
				'#%s: Mute list is empty!' % chan
			else:
				'#%s: Mute list (%i entries):'
				'Cranburry, indefinite time remaining'
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
		self.debug = False
		
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
		self.ChanServ = ChanServ(self, self._root)
		if protocol and not self._protocol:
			self._protocol = protocol
			self.ChanServ.onLogin()
		else:
			self._protocol = protocol

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
