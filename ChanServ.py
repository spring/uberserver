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
		self.bot = True
		self.user_id = None
		self.static = True

		self.username = 'ChanServ'
		self.password = 'ChanServ'
		self.lobby_id = 'ChanServ'
		self._root.usernames[self.username] = self
		self._root.clients[session_id] = self
		self._root = root

		self._root.protocol._calc_status(self, self.status)
		logging.info('[%s] <%s> logged in (access=ChanServ)'%(session_id, self.username))

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
		elif duration.endswith('w'):
			return timedelta(weeks=num)
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
		if msg[0] != ":":
			n = msg.find(' ')
			if n<0: n = len(msg)
			cmd = msg[:n]
			if chan == "moderator" and cmd in self._root.protocol.restricted['mod']:
				# allow some mod commands to be executed by simply typing into #moderator
				client = self._root.protocol.clientFromUsername(user)
				if client:
					self._root.protocol._handle(client, msg)
			if not chan: #pm to ChanServ
				self.Respond("SAYPRIVATE %s ChanServ commands must be prefixed by a colon e.g. ':help'" % (user, ))
			return
		msg = msg.lstrip(':')

		args = None
		if chan: # message picked up in a channel
			if ' ' in msg:
				cmd, args = msg.split(' ', 1)
			else:
				cmd = msg
		else: # message sent via pm
			n = msg.count(' ')
			if n >= 2:
				cmd, chan, args = msg.split(' ', 2)
			elif n == 1:
				cmd, chan = msg.split(' ', 1)
			else:
				cmd = msg

		response = self.HandleCommand(user, cmd, chan, args)
		if response:
			for s in response.split('\n'):
				self.Respond('SAYPRIVATE %s %s'%(user, s))

	def HandleCommand(self, user, cmd, chan=None, args=None):
		client = self._root.protocol.clientFromUsername(user)
		cmd = cmd.lower()

		if cmd == 'help':
			return 'Hello, %s!\nI am the server bot.\nFor the full list of my commands, see https://springrts.com/wiki/ChanServ\nIf you want to go ahead and register a new channel, please contact one of the server moderators!' % user

		if cmd == 'battlename':
			host = self._root.protocol.clientFromUsername(chan, True)
			if not host:
				return "User %s does not exist" % chan
			battle = self._root.protocol.getCurrentBattle(host)
			if not battle or battle.host != host.session_id:
				return "User %s is not hosting a battle" % chan
			return battle.name


		if not chan:
			return "Channel not specified"
		if chan[0] == '#':
			return 'ChanServ commands do not permit the # character to prefix channel names, please retry'


		if cmd == 'register':
			if not client.isMod():
				return '#%s: You must contact one of the server moderators to register a channel' % chan
			if not args: args = user
			target = self._root.protocol.clientFromUsername(args, True)
			if not target:
				return '#%s: User <%s> not found' % (chan, args)
			if not chan in self._root.channels:
				return 'Channel %s does not exist' % chan
			channel = self._root.channels[chan]
			if channel.registered():
				return "#%s: Already registered" % chan
			channel.register(client, target)
			self.Respond('JOIN %s' % chan)
			return '#%s: Successfully registered to <%s>' % (chan, args.split(' ',1)[0])


		if not chan in self._root.channels:
			return "Channel '%s' does not exist" % chan
		if not chan in self.channels:
			return "ChanServ is not present in channel '%s' (unregistered?)" % chan
		channel = self._root.channels[chan]
		access = channel.getAccess(client) #todo: cleaner code for access controls


		if cmd == 'unregister':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to unregister a channel' % chan
			if not channel.registered():
				return "#%s: Not registered" % chan
			channel.unregister(client)
			self.Respond('LEAVE %s' % chan)
			return '#%s: Successfully unregistered.' % chan

		if cmd == 'forward':
			if not client.isMod():
				return '#%s: You must contact one of the server moderators to add mute/ban forwarding' % chan
			if not args:
				return "#%s: You must specify a channel to forward mutes/bans to" % chan
			channel_from = channel
			args = args.lstrip('#')
			if not args in self._root.channels:
				return "Channel %s does not exist (missing #?)" % args
			channel_to = self._root.channels[args]
			if channel_from.identity!='channel' or channel_to.identity!='battle':
				return "#%s: To avoid circular dependencies, it is only permitted to forward mutes/bans from (non-battle) channels into battles" % chan
			if channel_to.name in channel_from.forwards:
				return "#%s: Forwarding of mutes/bans already exists to #%s" % (chan, channel_to.name)
			if not channel_to.registered():
				return "#%s: You must register %s before you can forward mutes/bans to it" % (chan, channel_to.name)
			channel_from.addForward(client, channel_to)
			return "#%s: Successfully added forwarding of mutes/bans to #%s" % (chan, channel_to.name)

		if cmd == 'unforward':
			if not client.isMod():
				return '#%s: You must contact one of the server moderators to remove mute/ban forwarding from a channel' % chan
			if not args:
				return "#%s: You must specify a channel to forward mutes/bans to" % chan
			channel_from = channel
			args = args.lstrip('#')
			if not args in self._root.channels:
				return "Channel %s does not exist (missing #?)" % args
			channel_to = self._root.channels[args]
			if not channel_to.name in channel_from.forwards:
				return "#%s: Forwarding of mutes/bans to #%s does not exist" % (chan, channel_to.name)
			channel_from.removeForward(client, channel_to)
			return "#%s: Successfully removed forwarding of mutes/bans to #%s" % (chan, channel_to.name)

		if cmd == 'listforwards':
			if len(channel.forwards)==0:
				return "#%s: Not forwarding to anywhere" % chan
			forwards_str = '#%s: Forwarding to' % chan
			for forward in channel.forwards:
				forwards_str += ' #' + forward
			return forwards_str

		if cmd == 'history':
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to change history settings in the channel' % chan
			if args=='on':
				channel.setHistory(client, True)
				return '#%s: History enabled' % (chan, str(enable))
			if args=='off':
				channel.setHistory(client, False)
				return '#%s: History disabled' % (chan, str(enable))
			return '#%s: Unknown value for history setting (expected: on, off).' % chan

		if cmd == 'antispam':
			if not access in ['mod', 'founder']:
				return '#%s: You must contact one of the server moderators or the owner of the channel to change the antispam settings' % chan
			if args == 'on':
				channel.setAntispam(client, True)
				return '#%s: Anti-spam protection is on.' % chan
			if args == 'off':
				channel.setAntispam(client, False)
				return '#%s: Anti-spam protection is off.' % chan
			return '#%s: Unknown value for anti-spam setting (expected: on, off).' % chan

		if cmd == 'setkey':
			if not access in ['mod', 'founder']:
				return '#%s: You do not have permission to change the channel password' % chan
			if not args:
				return "#%s: You must specify a password for the channel (use '*' for no password)" % chan
			if channel.identity=='battle':
				return 'This is not currently possible, instead you can close and re-open the battle with a new password!'
			channel.setKey(client, args)
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
			if ':' in target_username:
				return '#%s: Use !ban to remove a bridged user from the channel bridge (then, their chat will not be forwarded to #%s)' % (chan, chan)
			target = self._root.protocol.clientFromUsername(target_username, True)
			if not target:
				return '#%s: User <%s> not found' % (chan, target_username)
			if target.user_id in channel.mutelist:
				mute = channel.mutelist[target.user_id]
				issuer = self._root.protocol.clientFromID(mute['issuer_user_id'])
				if not issuer:
					return "#%s: User <%s> is already muted by <unknown user>" % (chan, target.username)
				return "#%s: User <%s> is already muted by <%s>" % (chan, target.username, issuer.username)
			if channel.isOp(target):
				return '#%s: Cannot mute <%s>, user has operator status' % (chan, target.username)
			try:
				expires = datetime.now() + duration
			except:
				expires = datetime.max
			channel.muteUser(client, target, expires, reason, duration)
			return '#%s: muted <%s> %s' % (chan, target.username, self._root.protocol.pretty_time_delta(duration))

		if cmd == 'unmute':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to unmute users in this channel' % chan
			target_username = args
			if not target_username:
				return '#%s: You must specify a user to unmute' % chan
			if ':' in target_username:
				return '#%s: For bridged users, use !ban/!unban' % (chan, chan)
			target = self._root.protocol.clientFromUsername(target_username, True)
			if not target or not target.user_id in channel.mutelist:
				return '#%s: User <%s> not found in mutelist' % (chan, target_username)
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
				target_username = "id:" + str(user_id)
				if target:
					target_username = target.username
				issuer = self._root.protocol.clientFromID(mute['issuer_user_id'], True)
				issuer_name_str = "unknown"
				if issuer:
					issuer_name_str = issuer.username
				mutelist_str += "\n" + "%s :: %s :: ends %s (%s)" % (target_username, mute['reason'], mute['expires'].strftime("%Y-%m-%d %H:%M:%S"), issuer_name_str)
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
			if ':' in target_username:
				target = self._root.bridgedClientFromUsername(target_username, True)
				if not target:
					return '#%s: Bridged user <%s> not found' % (chan, target_username)
				if target.bridged_id in channel.bridged_ban:
					ban = channel.bridged_ban[target.bridged_id]
					issuer = self._root.protocol.clientFromID(ban['issuer_user_id'])
					if not issuer:
						return "#%s: User <%s> is already banned by <unknown user>" % (chan, target.username)
					return "#%s: User <%s> is already banned by <%s>" % (chan, target.username, issuer.username)
				try:
					expires = datetime.now() + duration
				except:
					expires = datetime.max
				channel.banBridgedUser(client, target, expires, reason, duration)
				return '#%s: banned <%s> %s' % (chan, target.username, self._root.protocol.pretty_time_delta(duration))
			target = self._root.protocol.clientFromUsername(target_username, True)
			if not target:
				return '#%s: User <%s> not found' % (chan, target_username)
			if channel.isOp(target):
				return '#%s: Cannot ban <%s>, user has operator status' % (chan, target.username)
			if target.user_id in channel.ban and target.last_ip in channel.ban_ip:
				ban = channel.ban[target.user_id]
				issuer = self._root.protocol.clientFromID(ban['issuer_user_id'])
				if not issuer:
					return "#%s: User <%s, ip %s is already banned by <unknown user>" % (chan, target.username, ban.ip_address)
				return "#%s: User <%s>, ip %s is already banned by <%s>" % (chan, target.username, ban['ip_address'], issuer.username)
			try:
				expires = datetime.now() + duration
			except:
				expires = datetime.max
			channel.banUser(client, target, expires, reason, duration)
			return '#%s: banned <%s> %s' % (chan, target.username, self._root.protocol.pretty_time_delta(duration))

		if cmd == 'unban':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to unban users from this channel' % chan
			if not args:
				return '#%s: You must specify a user to unban from the channel' % chan
			target_username = args
			if ':' in target_username:
				target = self._root.bridgedClientFromUsername(target_username, True)
				if not target:
					return '#%s: User <%s> not found on the bridge' % (chan, target_username)
				if not target.bridged_id in channel.bridged_ban:
					return '#%s: User <%s> not found in bridged banlist' % (chan, target.username)
				channel.unbanBridgedUser(client, target)
				return '#%s: <%s> unbanned' % (chan, target.username)
			target = self._root.protocol.clientFromUsername(target_username, True)
			if not target or not target.user_id in channel.ban:
				return '#%s: User <%s> not found in banlist' % (chan, target.username)
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
				banlist_str += "\n" + "%s :: %s :: %s :: ends %s (%s)" % (target.username, ban['ip_address'], ban['reason'], ban['expires'].strftime("%Y-%m-%d %H:%M:%S"), issuer_name_str)
			for bridged_id in channel.bridged_ban:
				ban = channel.bridged_ban[bridged_id]
				target = self._root.bridgedClientFromID(bridged_id, True)
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
			channel.kickUser(client, target)
			return '#%s: kicked <%s>' % (chan, target.username)

		if cmd == 'topic':
			if not access in ['mod', 'founder', 'op']:
				return '#%s: You do not have permission to set the topic' % chan
			args = args or ''
			channel.setTopic(client, args)
			return '#%s: Topic changed' % chan

		if cmd == 'info':
			antispam = "Anti-spam protection is off"
			if channel.antispam:
				antispam = "Anti-spam protection is on"
			founder = 'No founder is registered'
			if channel.owner_user_id:
				founder = self._root.protocol.clientFromID(channel.owner_user_id, True)
				if founder: founder = 'Founder is <%s>' % founder.username
			operators = channel.operators
			op_list = "Operator list is "
			separator = '['
			for op_user_id in operators:
				op_entry = self._root.protocol.clientFromID(op_user_id, True)
				if op_entry:
					op_list += separator + op_entry.username
					if separator == '[': separator = ' '
				if separator == ' ': op_list += ']'
			if separator!=' ': op_list += 'empty'
			users = channel.users
			bridged_users = channel.bridged_users
			users_str = 'Currently contains 0 users and 0 bridged users'
			if len(users)>=1 or len(bridged_users)>=1:
				users_str = 'Currently contains %i users and %i bridged users' % (len(users), len(bridged_users))
			return '#%s info: %s. %s. %s. %s. ' % (chan, antispam, founder, op_list, users_str)

		if not (len(cmd)>=3 and all(c.isalpha() for c in cmd)):
			return #probably just a smiley or suchlike - not meant to invoke ChanServ
		
		return "command '%s' does not exist, try ':help' to get help" %(cmd) #todo: better cmd list + split into functions

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

