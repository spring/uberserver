import time, traceback, logging
from Client import Client

class ChanServClient(Client):
	def __init__(self, root, address, session_id):
		'initial setup for the connected client'
		Client.__init__(self, root, address, session_id)

		self.accesslevels = ['admin', 'mod', 'user', 'everyone']
		self.logged_in = True
		self.connected = True
		self.bot = 1
		self.user_id = None
		self.static = True

		self.username = 'ChanServ'
		self.password = 'ChanServ'
		self.lobby_id = 'ChanServ'
		self._root.usernames[self.username] = self
		self._root.clients[session_id] = self
		self._root = root

		logging.info('[%s] <%s> logged in (access=ChanServ)'%(session_id, self.username))

	def db(self):
		return self._root.channeldb

	def Handle(self, msg):
		try:
			if not msg.count(' '):
				return
			cmd, args = msg.split(' ', 1)
			if cmd == 'SAID':
				chan, user, msg = args.split(' ',2)
				self.HandleMessage(chan, user, msg)
			if cmd == 'SAIDPRIVATE':
				user, msg = args.split(' ', 1)
				self.HandleMessage(None, user, msg)
		except:
			logging.error(traceback.format_exc())

	def Respond(self, msg):
		'''
		Send data to the lobby server
		'''
		self._root.protocol._handle(self, msg)

	def HandleMessage(self, chan, user, msg):
		if len(msg) <= 0:
			return
		if msg[0] != "!":
			return
		msg = msg.lstrip('!')
		args = None
		if user == 'ChanServ': return # safety, shouldn't be needed
		if msg.count(' ') >= 2:	# case cmd blah blah+
			splitmsg = msg.split(' ',2)
			if splitmsg[1].startswith('#'): # case cmd #chan arg+
				cmd, chan, args = splitmsg
				chan = chan.lstrip('#')
			else: # case cmd arg arg+
				cmd, args = msg.split(' ',1)
		elif msg.count(' ') == 1: # case cmd arg
			splitmsg = msg.split(' ')
			if splitmsg[1].startswith('#'): # case cmd #chan
				cmd, chan = splitmsg
				chan = chan.lstrip('#')
			else: # case cmd arg
				cmd, args = splitmsg
		else: # case cmd
			cmd = msg
		response = self.HandleCommand(chan, user, cmd, args)
		if response:
			for s in response.split('\n'):
				self.Respond('SAYPRIVATE %s %s'%(user, s))


	def HandleCommand(self, chan, user, cmd, args=None):
		client = self._root.protocol.clientFromUsername(user)
		cmd = cmd.lower()
		if cmd == 'help':
			return 'Hello, %s!\nI am an automated channel service bot from uberserver,\nfor the full list of commands, see https://springrts.com/dl/ChanServCommands.html\nIf you want to go ahead and register a new channel, please contact one of the server moderators!' % user

		if chan in self._root.channels:
			channel = self._root.channels[chan]
			access = channel.getAccess(client)
			if cmd == 'info':
				antispam = 'on' if channel.antispam else 'off'
				founder = 'No founder is registered'				
				if channel.owner_user_id:
					founder = self._root.protocol.clientFromID(channel.owner_user_id, True)
					if founder: founder = 'Founder is <%s>' % founder.username
				operators = channel.operators
				op_list = "operator list is "
				separator = '['
				for op_user_id in operators:
					op_entry = self._root.protocol.clientFromID(op_user_id, True)
					if op_entry:
						op_list += separator + op_entry.username
						if separator == '[': separator = ' '
					if separator == ' ': op_list += ']'
				if separator!=' ': op_list += 'empty'						
				users = channel.users
				if len(users) == 1: users = '1 user is'
				else: users = '%i users are currently in the channel' % len(users)
				return '#%s info: Anti-spam protection is %s. %s, %s. %s. ' % (chan, antispam, founder, op_list, users)
			elif cmd == 'topic':
				if access in ['mod', 'founder', 'op']:
					args = args or ''
					channel.setTopic(client, args)
					self.db().setTopic(channel, args, client) 
					return '#%s: Topic changed' % chan
				else:
					return '#%s: You do not have permission to set the topic' % chan
			elif cmd == 'unregister':
				if access in ['mod', 'founder']:
					channel.owner_user_id = None
					channel.operators = set()
					channel.channelMessage('#%s has been unregistered'%chan)
					self.db().unRegister(client, channel)
					return '#%s: Successfully unregistered.' % chan
				else:
					return '#%s: You must contact one of the server moderators or the owner of the channel to unregister a channel' % chan
			elif cmd == 'changefounder':
				if access in ['mod', 'founder']:
					if not args: return '#%s: You must specify a new founder' % chan
					target = self._root.protocol.clientFromUsername(args, True)
					if not target: return '#%s: cannot assign founder status to a user who does not exist'
					channel.setFounder(client, target)
					channel.channelMessage('%s Founder has been changed to <%s>' % (chan, args))
					self.db().setFounder(channel, target)
					return '#%s: Successfully changed founder to <%s>' % (chan, args)
				else:
					return '#%s: You must contact one of the server moderators or the owner of the channel to change the founder' % chan
			elif cmd == 'spamprotection':
				if access in ['mod', 'founder']:
					if args == 'on':
						channel.antispam = True
						channel.channelMessage('%s Anti-spam protection was enabled by <%s>' % (chan, user))
						return '#%s: Anti-spam protection is on.' % chan
					elif args == 'off':
						channel.antispam = False
						channel.channelMessage('%s Anti-spam protection was disabled by <%s>' % (chan, user))
						return '#%s: Anti-spam protection is off.' % chan
				
				status = 'off'
				if channel.antispam: status = 'on'
				return '#%s: Anti-spam protection is %s' % (chan, status)
			elif cmd == 'op':
				if access in ['mod', 'founder']:
					if not args: return '#%s: You must specify a user to op' % chan
					target = self._root.protocol.clientFromUsername(args, True)
					if not target: return '#%s: cannot assign operator status, user does not exist' 
					if target and channel.isOp(target): return '#%s: <%s> was already an op' % (chan, args)
					channel.opUser(client, target)
					self.db().opUser(channel, target)
					return '#%s: Successfully added <%s> to operator list' % (chan, args)
				else:
					return '#%s: You do not have permission to op users' % chan
			elif cmd == 'deop':
				if access in ['mod', 'founder']:
					if not args: return '#%s: You must specify a user to deop' % chan
					target = self._root.protocol.clientFromUsername(args, True)
					if not target: return '#%s: cannot remove operator status, user does not exist'
					if target.user_id==channel.owner_user_id: return '#%s: cannot remove operator status from channel founder'
					if target and not channel.isOp(target): return '#%s: <%s> was not an op' % (chan, args)
					channel.deopUser(client, target)
					self.db().deopUser(channel, target)
					return '#%s: Successfully removed <%s> from operator list' % (chan, args)
				else:
					return '#%s: You do not have permission to deop users' % chan
			elif cmd == 'lock':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a channel key to lock a channel' % chan
					channel.setKey(client, args)
					self.db().setKey(channel, args)
					## STUBS ARE BELOW
					return '#%s: Locked' % chan
				else:
					return '#%s: You do not have permission to lock the channel' % chan
			elif cmd == 'unlock':
				if access in ['mod', 'founder', 'op']:
					channel.setKey(client, '*')
					self.db().setKey(channel, '*')
					return '#%s: Unlocked' % chan
				else:
					return '#%s: You do not have permission to unlock the channel' % chan
			elif cmd == 'kick':
				if access in ['mod', 'founder', 'op']:
					if not args: return '#%s: You must specify a user to kick from the channel' % chan
					
					if args.count(' '):
						target, reason = args.split(' ', 1)
					else:
						target = args
						reason = None
						
					if target in channel.users:
						target = self._root.clientFromUsername(target)
						channel.kickUser(client, target, reason)
						return '#%s: <%s> kicked' % (chan, target.username)
					else: return '#%s: <%s> not in channel' % (chan, target)
				else:
					return '#%s: You do not have permission to kick users from the channel' % chan
			elif cmd == 'history':
				if access in ['mod', 'founder', 'op']:
					enable = not channel.store_history
					if self.db().setHistory(channel, enable):
						channel.store_history = enable
						msg = '#%s: history enabled=%s' % (chan, str(enable))
					else:
						msg = '#%s: history not enabled, register it first!' % (chan)
					channel.channelMessage(msg)
					return msg
				else:
					return '#%s: You do not have permission to change history setting in the channel' % chan
		if cmd == 'register':
			if client.isMod():
				if not args: args = user
				self.Respond('JOIN %s' % chan)
				if not chan in self._root.channels:
					return '# Channel %s does not exist.' % (chan)
				channel = self._root.channels[chan]
				target = self._root.protocol.clientFromUsername(args, True)
				if target:
					channel.setFounder(client, target)
					self.db().register(channel, target) # register channel in db
					return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])
				else:
					return '#%s: User <%s> does not exist.' % (chan, args)
			elif not chan in self._root.channels:
				return '#%s: You must contact one of the server moderators or the owner of the channel to register a channel' % chan
		if not chan:
			return 'command "%s" not found, use "!help" to get help!' %(cmd)
	
	def Remove(self, reason=None):
		pass

	def Send(self, data):
		""" called by lobby server. ~Receive """
		self.RealSend(data)

	def RealSend(self, msg):
		""" called by lobby server. ~Receive """
		if not msg:
			return
		self.Handle(msg)


	def FlushBuffer(self):
		pass

