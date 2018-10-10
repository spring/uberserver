import time, traceback, logging
from Client import Client

class ChanServClient(Client):
	# manages interaction between database and channel mods/founders/ops
	
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

						
	#FIXME: chanserv has no mute command
	#FIXME: accept ymdhs durations for mutes/bans
	#FIXME: ban should interact with ip & email ?
	
	def HandleCommand(self, chan, user, cmd, args=None):
		client = self._root.protocol.clientFromUsername(user)
		access = channel.getAccess(client) #todo: cleaner code for access controls
		cmd = cmd.lower()

		if cmd == 'help':
			return 'Hello, %s!\nI am an automated channel service bot from uberserver,\nfor the full list of commands, see https://springrts.com/dl/ChanServCommands.html\nIf you want to go ahead and register a new channel, please contact one of the server moderators!' % user
		
		if not chan in self._root.channels:
			return "Channel %s does not exist!"
		channel = self._root.channels[chan]
		
		if cmd == 'register': 
			if not client.isMod():
				return '#%s: You must contact one of the server moderators to register a channel' % chan
			if chan.startwith('__battle__'):
				return "#%s: This channel is part of a battle, please use !registerbattle instead" % chan
			if not args: args = user
			target = self._root.protocol.clientFromUsername(args, True)
			if not target:
				return '#%s: User <%s> does not exist.' % (chan, args)
			channel = self._root.channels[chan]
			channel.register(client, target)
			self.db().register(channel, target) # register channel in db
			self.Respond('JOIN %s' % chan)
			return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])
			
		if cmd == 'registerbattle': 
			if client.isMod():
				return '#%s: You must contact one of the server moderators to register a battle' % chan
			if args.count(' '):
				battle_username, target_username = args.split(' ', 1)
			else:
				battle_username = args
				target_username = user
			target_user = self._root.protocol.clientFromUsername(target_username, True)
			if not target_user:					
				return 'User %s does not exist' % target_username			
			battle_user = self._root.protocol.clientFromUsername(battle_username, True)
			if not battle_user:
				return 'User %s does not exist' % battle_username
			if not self._root.protocol.getCurrentBattle(battle_user):
				return 'User %s is not hosting a battle right now' % battle_username
			chan = '__battle__' + str(battle_user.user_id)
			if not chan in self._root.channels:
				return 'Channel for battle %s hosted by user_id %i does not exist, this is bug, please tell someone!' % (chan, user.user_id)
			channel = self._root.channels[chan]
			if not target:
				return '#%s: User <%s> does not exist.' % (chan, args)
			channel.register(client, target)
			self.db().register(channel, target) # register channel in db
			self.Respond('JOIN %s' % chan)
			return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])		

		if cmd == 'unregister':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to unregister a channel' % chan
			channel.owner_user_id = None
			channel.operators = set()
			channel.channelMessage('#%s has been unregistered'%chan)
			self.db().unRegister(client, channel)
			self.Respond('LEAVE %s' % chan)
			return '#%s: Successfully unregistered.' % chan

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
		
		if cmd == 'topic':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to set the topic' % chan
			args = args or ''
			channel.setTopic(client, args)
			self.db().setTopic(channel, args, client) 
			return '#%s: Topic changed' % chan

		if cmd == 'changefounder':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to change the founder' % chan
			if not args: return '#%s: You must specify a new founder' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target: return '#%s: cannot assign founder status to a user who does not exist'
			channel.setFounder(client, target)
			channel.channelMessage('%s Founder has been changed to <%s>' % (chan, args))
			self.db().setFounder(channel, target)
			return '#%s: Successfully changed founder to <%s>' % (chan, args)
		
		if cmd == 'spamprotection':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to change the antispam settings' % chan
			if args == 'on':
				channel.antispam = True
				channel.channelMessage('%s Anti-spam protection was enabled by <%s>' % (chan, user))
				return '#%s: Anti-spam protection is on.' % chan
			channel.antispam = False
			channel.channelMessage('%s Anti-spam protection was disabled by <%s>' % (chan, user))
			return '#%s: Anti-spam protection is off.' % chan
		
		if cmd == 'op':
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to op users' % chan
			if not args: 
				return '#%s: You must specify a user to op' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target: 
				return '#%s: cannot assign operator status, user does not exist' 
			if target and channel.isOp(target): 
				return '#%s: <%s> was already an op' % (chan, args)
			channel.opUser(client, target)
			self.db().opUser(channel, target)
			return '#%s: Successfully added <%s> to operator list' % (chan, args)
		
		if cmd == 'deop':
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to deop users' % chan
			if not args: 
				return '#%s: You must specify a user to deop' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target: 
				return '#%s: cannot remove operator status, user does not exist'
			if target.user_id==channel.owner_user_id: return '#%s: cannot remove operator status from channel founder'
			if target and not channel.isOp(target): return '#%s: <%s> was not an op' % (chan, args)
			channel.deopUser(client, target)
			self.db().deopUser(channel, target)
			return '#%s: Successfully removed <%s> from operator list' % (chan, args)

		if cmd == 'setkey': 
			if access in ['mod', 'founder', 'op']:
				if not args: 
					return '#%s: You must specify a key for the channel' % chan
				if channel.identity=='battle': 
					return 'This is not currently possible, instead you can close and re-open the battle with a new password!'
				channel.setKey(client, args)
				self.db().setKey(channel, args)
				return '#%s: Set key' % chan
			else:
				return '#%s: You do not have permission to lock the channel' % chan
		
		if cmd == 'removekey': 
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to unlock the channel' % chan
			if channel.identity=='battle': 
				return 'This is not currently possible, instead you can close and re-open the battle without a password!'
			channel.setKey(client, '*')
			self.db().setKey(channel, '*')
			return '#%s: Removed key' % chan
		
		if cmd == 'kick':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to kick users from the channel' % chan
			if not args: 
				return '#%s: You must specify a user to kick from the channel' % chan
			if args.count(' '):
				target, reason = args.split(' ', 1)
			else:
				target = args
				reason = None						
			if not target in channel.users:
				return '#%s: user <%s> not found' % (chan, target)
			target = self._root.protocol.clientFromUsername(target, True)
			channel.kickUser(client, target, reason)
			return '#%s: <%s> kicked' % (chan, target.username)
		
		if cmd == 'history': #FIXME: limit battles to a short history
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to change history setting in the channel' % chan
			enable = not channel.store_history
			if self.db().setHistory(channel, enable):
				channel.store_history = enable
				msg = '#%s: history enabled=%s' % (chan, str(enable))
			else:
				msg = '#%s: history not enabled, register it first!' % (chan)
			channel.channelMessage(msg)
			return msg
		
		if cmd == 'ban':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to ban users from this channel' % chan					
			if not args: return '#%s: You must specify a user to ban from the channel' % chan					
			if args.count(' '):
				target_username, reason = args.split(' ', 1)
			else:
				target_username = args
				reason = None
			if not '@' in target_username:
				target = self._root.protocol.clientFromUsername(target_username, True)
				if target:
					channel.banUser(client, target, reason)
					return '#%s: <%s> banned' % (chan, target.username)
			elif '@' in target_username:
				target = self._root.protocol.bridgedClientFromUsername(target_username)
				if target:
					channel.banBridgedUser(client, target, reason)
					return '#%s: <%s> banned' % (chan, target.username)
				return '#%s: user <%s> not found' % (chan, target_username)						
		
		if cmd == 'unban':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to ban users from this channel' % chan	
			if not args: return '#%s: You must specify a user to unban from the channel' % chan					
			if args.count(' '):
				target_username, reason = args.split(' ', 1)
			else:
				target_username = args
				reason = None
			if not '@' in target_username:
				target = self._root.protocol.clientFromUsername(target_username, True)
				if target and target_username in channel.ban:
					channel.unbanUser(client, target, reason)
					return '#%s: <%s> unbanned' % (chan, target.username)
			elif '@' in target_username:
				target = self._root.protocol.bridgedClientFromUsername(target_username)
				if target and target.bridged_id in channel.bridged_ban:
					channel.unbanBridgedUser(client, target)
					return '#%s: <%s> unbanned' % (chan, target.username)
			return '#%s: user <%s> not found in banlist' % (chan, target_username)
		
		if cmd == 'lock' or cmd == 'unlock':
			return 'This command no longer exists, use !setkey/!removekey'
		
		return 'command "%s" not found, use "!help" to get help!' %(cmd) #todo: better cmd list + split into functions
	
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

