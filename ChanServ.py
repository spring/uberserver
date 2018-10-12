import time, traceback, logging
from datetime import timedelta
from datetime import datetime
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
		
	def parse_duration(self, duration):
		try:
			num = int(duration)
			if num <= 0: return timedelta.max
			return timedelta(minutes=num)
		except:
			pass
		try:
			num = int(duration[:-1])
			if num <= 0: return timedelta.max
		except:
			return
		if duration.endswith('m'):
			return timedelta(minutes=num)
		elif duration.endswith('h'):
			return timedelta(hours=num)
		elif duration.endswith('d'):
			return timedelta(days=num)	
		return
		
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
			if cmd == 'SAIDBATTLE': #legacy compat, if clients lacks 'u'
				user, msg = args.split(' ', 1)
				client = self._root.protocol.clientFromUsername(user)
				battle = self._root.protocol.getCurrentBattle(client)
				chan = battle.name
				self.HandleMessage(chan, user, msg)				
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
		
		if cmd == 'battlename':
			host = self._root.protocol.clientFromUsername(args, True)
			if not host:
				return "User %s does not exist" % args
			battle = self._root.protocol.getCurrentBattle(host)
			if not battle or battle.host != host.session_id:
				return "User %s is not hosting a battle" % args
			return battle.name
		
		if cmd == 'register': 
			if not client.isMod():
				return '#%s: You must contact one of the server moderators to register a channel' % chan
			if not chan:
				return 'Channel not found (missing #?)'
			if not args: args = user
			target = self._root.protocol.clientFromUsername(args, True)
			if not target:
				return '#%s: User <%s> not found' % (chan, args)
			if not chan in self._root.channels:
				return 'Channel %s does not exist' % chan
			channel = self._root.channels[chan]
			channel.register(client, target)
			self.db().register(channel, target) # register channel in db
			self.Respond('JOIN %s' % chan)
			return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])		
		

		if not chan in self._root.channels:
			return "Channel %s does not exist!" % chan
		channel = self._root.channels[chan]
		access = channel.getAccess(client) #todo: cleaner code for access controls
		
		
		if cmd == 'unregister':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to unregister a channel' % chan
			channel.ChanServ = False
			channel.owner_user_id = None
			channel.operators = set()
			channel.channelMessage('#%s has been unregistered'%chan)
			self.db().unRegister(client, channel)
			self.Respond('LEAVE %s' % chan)
			return '#%s: Successfully unregistered.' % chan
		
		if cmd == 'setkey': 
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to change the channel password' % chan
			if not args: 
				return "#%s: You must specify a password for the channel (use '*' for no password)" % chan
			if channel.identity=='battle': 
				return 'This is not currently possible, instead you can close and re-open the battle with a new password!'
			channel.setKey(client, args)
			self.db().setKey(channel, args)
			return '#%s: Set key' % chan
		
		if cmd == 'op':
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to op users' % chan
			if not args: 
				return '#%s: You must specify a user to op' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target: 
				return '#%s: User <%s> not found' % (chan, args)
			if channel.isOp(target): 
				return '#%s: <%s> was already an op' % (chan, args)
			channel.opUser(client, target)
			self.db().opUser(channel, target)
			return '#%s: added <%s> to operator list' % (chan, args)
		
		if cmd == 'deop':
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to deop users' % chan
			if not args: 
				return '#%s: You must specify a user to deop' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target: 
				return '#%s: User <%s> not found' % (chan, args)
			if target.user_id==channel.owner_user_id: 
				return '#%s: Cannot remove operator status from channel founder' % chan
			if target and not channel.isOp(target): 
				return '#%s: <%s> was not an op' % (chan, args)
			channel.deopUser(client, target)
			self.db().deopUser(channel, target)
			return '#%s: removed <%s> from operator list' % (chan, args)

		if cmd == 'changefounder':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to change the founder' % chan
			if not args: 
				return '#%s: You must specify a new founder' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target: 
				return '#%s: Cannot assign founder status to a user who does not exist'
			channel.setFounder(client, target)
			self.db().setFounder(channel, target)
			return '#%s: changed founder to <%s>' % (chan, args)

		
		if cmd == 'mute': 
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to mute users in this channel' % chan
			if args.count(' ') >= 2:
				target_username, duration_str, reason = args.split(' ', 2) 
			if args.count(' ') < 2 or not target_username or not duration_str or not reason:
				return "#%s: Please specify a target username, a duration, and a reason (in that order)"
			duration = self.parse_duration(duration_str)
			if duration == None:
				return "#%s: Could not parse duration %s, please enter a number of minutes or specify a time unit e.g. '10m', '2h', or '3d'" % (chan, duration_str)
			if '@' in target_username:
				return '#%s: Use !ban to remove a bridged user from the channel bridge (then, their chat will not be forwarded to #%s)' % (chan, chan)
			target = self._root.protocol.clientFromUsername(target_username, True)			
			if not target:
				return '#%s: User <%s> not found' % (chan, target_username)
			if channel.isOp(target):
				return '#%s: Cannot mute <%s>, user has operator status' % (chan, target.username)	
			channel.muteUser(client, target, duration, reason)
			return '#%s: muted <%s> %s' % (chan, target.username, self._root.protocol.pretty_time_delta(duration))
		
		if cmd == 'unmute':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to unmute users in this channel' % chan					
			target_username = args
			if not target_username: 
				return '#%s: You must specify a user to unmute' % chan					
			if '@' in target_username:
				return '#%s: For bridged users, use !ban/!unban' % (chan, chan)
			target = self._root.protocol.clientFromUsername(target_username, True)			
			if not target or not target.user_id in channel.mutelist:
				return '#%s: User <%s> not found in mutelist' % (chan, target)
			channel.unmuteUser(client, target)
			return '#%s: unmuted <%s>' % (chan, target.username)
		
		if cmd == 'listmutes':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to execute this command' % chan	
			if len(channel.mutelist) == 0:
				return "The mutelist is empty."
			mutelist_str = " -- Mutelist for %s -- " % chan
			for user_id in channel.mutelist:
				mute = channel.mutelist[user_id]
				target = self._root.protocol.clientFromID(user_id, True)
				if not target:
					continue
				issuer = self._root.protocol.clientFromID(mute['issuer_user_id'], True)
				issuer_name_str = "unknown"
				if issuer:
					issuer_name_str = issuer.username
				mutelist_str += "\n" + "%s :: %s :: ends %s (%s)" % (target.username, mute['reason'], mute['expires'].strftime("%Y-%m-%d %H:%M:%S"), issuer_name_str)
			mutelist_str += "\n" + " -- End Mutelist -- " 
			return mutelist_str
		
		if cmd == 'ban':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to ban users from this channel' % chan
			if args.count(' ') >= 2:
				target_username, duration_str, reason = args.split(' ', 2) 
			if args.count(' ') < 2 or not target_username or not duration_str or not reason:
				return "#%s: Please specify a target username, a duration, and a reason (in that order)"
			duration = self.parse_duration(duration_str)
			if duration == None:
				return "#%s: Could not parse duration %s, please enter a number of minutes or specify a time unit e.g. '10m', '2h', or '3d'" % (chan, duration_str)
			if '@' in target_username:
				target = self._root.protocol.bridgedClientFromUsername(target_username)
				if not target:
					return '#%s: Bridged user <%s> not found' % (chan, target_username)						
				channel.banBridgedUser(client, target, duration, reason)
				return '#%s: banned <%s> from %s' % (chan, target.username, duration)
			target = self._root.protocol.clientFromUsername(target_username, True)
			if not target:
				return '#%s: User <%s> not found' % (chan, target_username)	
			if channel.isOp(target):
				return '#%s: Cannot ban <%s>, user has operator status' % (chan, target.username)	
			channel.banUser(client, target, duration, reason)
			return '#%s: banned <%s> %s' % (chan, target.username, self._root.protocol.pretty_time_delta(duration))
			
		if cmd == 'unban':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to unban users from this channel' % chan	
			if not args: 
				return '#%s: You must specify a user to unban from the channel' % chan					
			target_username = args
			if '@' in target_username:
				target = self._root.protocol.bridgedClientFromUsername(target_username)
				if not target or not target.bridged_id in channel.bridged_ban:
					return '#%s: User <%s> not found in bridged banlist' % (chan, target_username)
				channel.unbanBridgedUser(client, target)
				return '#%s: <%s> unbanned' % (chan, target.username)
			target = self._root.protocol.clientFromUsername(target_username, True)
			if not target or not target.user_id in channel.ban:
				return '#%s: User <%s> not found in banlist' % (chan, target_username)
			channel.unbanUser(client, target)
			return '#%s: <%s> unbanned' % (chan, target.username)
		
		if cmd == 'listbans':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to execute this command' % chan	
			if len(channel.ban) + len(channel.bridged_ban) == 0:
				return "The banlist is empty."
			banlist_str = " -- Banlist for %s -- " % chan
			for user_id in channel.ban:
				ban = channel.ban[user_id]
				target = self._root.protocol.clientFromID(user_id, True)
				if not target:
					continue
				issuer = self._root.protocol.clientFromID(ban['issuer_user_id'], True)
				issuer_name_str = "unknown"
				if issuer:
					issuer_name_str = issuer.username
				banlist_str += "\n" + "%s :: %s :: ends %s (%s)" % (target.username, ban['reason'], ban['expires'].strftime("%Y-%m-%d %H:%M:%S"), issuer_name_str)
			for user_id in channel.bridged_ban:
				ban = channel.bridged_ban[user_id]
				target = self._root.protocol.clientFromID(user_id)
				if not target:
					continue
				issuer = self._root.protocol.clientFromID(ban['issuer_user_id'])
				issuer_name_str = "unknown"
				if issuer:
					issuer_name_str = issuer.username
				banlist_str += "\n" + "%s :: %s :: ends %s (%s)" % (target.username, ban['reason'], ban['expires'].strftime("%Y-%m-%d %H:%M:%S"), issuer_name_str)
			banlist_str += "\n" + " -- End Banlist -- "
			return banlist_str
		
		if cmd == 'kick': 
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to kick users from the channel' % chan
			target_username = args
			if not target_username: 
				return '#%s: You must specify a user to kick from the channel' % chan
			target = self._root.protocol.clientFromUsername(args, True)
			if not target or not target.session_id in channel.users:
				return '#%s: User <%s> not found' % (chan, target_username)
			if channel.isOp(target):
				return '#%s: Cannot kick <%s>, user has operator status' % (chan, target.username)	
			channel.kickUser(client, target, reason)
			return '#%s: kicked <%s>' % (chan, target.username)
		
		if cmd == 'topic':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to set the topic' % chan
			args = args or ''
			channel.setTopic(client, args)
			self.db().setTopic(channel, args, client) 
			return '#%s: Topic changed' % chan
	
		if cmd == 'spamprotection':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to change the antispam settings' % chan
			if args == 'on':
				channel.antispam = True
				channel.channelMessage('%s Anti-spam protection was enabled by <%s>' % (chan, user))
				return '#%s: Anti-spam protection is on.' % chan
			channel.antispam = False
			channel.channelMessage('%s Anti-spam protection was disabled by <%s>' % (chan, user))
			return '#%s: Anti-spam protection is off.' % chan
		
		
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
		
		if cmd == 'history': 
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
		
		
		if cmd == 'lock' or cmd == 'unlock':
			return 'This command no longer exists, use !setkey'
		
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

