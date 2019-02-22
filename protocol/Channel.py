import time
from datetime import datetime
from datetime import timedelta

class Channel():
	def __init__(self, root, name):
		self._root = root
		self.identity = 'channel'

		# db fields
		self.id = 0 #id 0 is used for all unregistered channels (<-> channel not in db)
		self.name = name
		self.key = None
		self.owner_user_id = None # 'founder'
		self.topic = ''
		self.topic_time = None # deprecated
		self.topic_user_id = None
		self.antispam = False
		self.autokick = '' #deprecated
		self.censor = False
		self.antishock = False #deprecated
		self.store_history = False

		# non-db fields
		self.operators = set() #user_ids
		self.users = set() # session_ids
		self.bridged_users = set() #bridged_ids
		
		self.topic_username = ''
		self.mutelist = {} #user_id -> mute
		self.ban = {} #user_id -> ban
		self.ban_ip = {} #ip -> ban
		self.bridged_ban = {} #bridged_ids

		self.forwards = set() #channel_names


	def db(self):
		return self._root.channeldb

	def broadcast(self, message, ignore=set(), flag=None, not_flag=None):
		self._root.broadcast(message, self.name, ignore, None, flag, not_flag)

	def channelMessage(self, message):
		if self.identity == 'battle': # backwards compat for clients lacking 'u'
			self.broadcast('CHANNELMESSAGE %s %s' % (self.name, message), set(), 'u')
			return
		self.broadcast('CHANNELMESSAGE %s %s' % (self.name, message))

	def register(self, client, target):
		self.setFounder(client, target)
		self.db().register(self, target)

	def unregister(self, client):
		self.owner_user_id = None
		self.topic = None
		self.operators = set()
		self.channelMessage('This channel has been unregistered by <%s>' % client.username)
		self.db().unRegister(self)

	def registered(self):
		return self.db().registered(self)

	def addUser(self, client):
		if client.session_id in self.users:
			return
		self.users.add(client.session_id)
		client.channels.add(self.name)
		
		flag = 'u' if self.identity=="battle" else None # for legacy clients without 'u', who are not told that they and others are are in the __battle__ channel! 
		if flag and not flag in client.compat:
			self.broadcast('JOINED %s %s' % (self.name, client.username), set(), flag)		
			return			
		client.Send('JOIN %s' % self.name)	
		self.broadcast('JOINED %s %s' % (self.name, client.username), set(), flag)		
		
		topic_client = self._root.protocol.clientFromID(self.topic_user_id) if self.topic_user_id else None
		topic_username = topic_client.username if topic_client else 'ChanServ'
		if 't' in client.compat:
			client.Send('CHANNELTOPIC %s %s %s' % (self.name, topic_username, self.topic))
		if len(self.topic)>0 and not 't' in client.compat:
			client.Send('CHANNELTOPIC %s %s %s %s' % (self.name, topic_username, time.time(), self.topic)) # backwards compat
				
		if 'u' in client.compat:
			bridgedClients = {}
			for bridged_id in self.bridged_users:
				bridgedClient = self._root.bridgedClientFromID(bridged_id)
				bridge = self._root.clientFromID(bridgedClient.bridge_user_id) 
				if not bridge.username in bridgedClients:
					bridgedClients[bridge.username] = ""
				if bridgedClients[bridge.username] != "":
					bridgedClients[bridge.username] += " "
				bridgedClients[bridge.username] += bridgedClient.username
			for bridge_username in bridgedClients:
				client.Send('CLIENTSFROM %s %s %s' % (self.name, bridge_username, bridgedClients[bridge_username]))

		clientlist = ""
		for session_id in self.users:
			if clientlist:
				clientlist += " "
			channeluser = self._root.protocol.clientFromSession(session_id)
			assert(channeluser)
			clientlist += channeluser.username
		client.Send('CLIENTS %s %s' % (self.name, clientlist))

	def removeUser(self, client, reason=None):
		if self.name in client.channels:
			client.channels.remove(self.name)
		if not client.session_id in self.users:
			return
		self.users.remove(client.session_id)
		
		flag = 'u' if self.identity=="battle" else None # for legacy clients without 'u' 
		if reason:
			self.broadcast('LEFT %s %s %s' % (self.name, client.username, reason), set(), flag)
		else:
			self.broadcast('LEFT %s %s' % (self.name, client.username), set(), flag)

	def addBridgedUser(self, client, bridgedClient):
		bridged_id = bridgedClient.bridged_id
		if bridged_id in self.bridged_users:
			return
		self.bridged_users.add(bridged_id)
		bridgedClient.channels.add(self.name)
		bridge = self._root.clientFromID(bridgedClient.bridge_user_id) 
		self.broadcast('JOINEDFROM %s %s %s' % (self.name, bridge.username, bridgedClient.username), set(), 'u')

	def removeBridgedUser(self, client, bridgedClient, reason=''):
		bridged_id = bridgedClient.bridged_id
		if not bridged_id in self.bridged_users:
			return
		self.bridged_users.remove(bridged_id)
		bridgedClient.channels.remove(self.name)
		self.broadcast('LEFTFROM %s %s %s' % (self.name, bridgedClient.username, reason), set(), 'u')

	def isAdmin(self, client):
		return client and ('admin' in client.accesslevels)

	def isMod(self, client):
		return client and (('mod' in client.accesslevels) or self.isAdmin(client))

	def isFounder(self, client):
		return client and ((client.user_id == self.owner_user_id) or self.isMod(client))

	def isOp(self, client):
		return client and ((client.user_id in self.operators) or self.isFounder(client))

	def getAccess(self, client):
		return 'mod' if self.isMod(client) else\
				('founder' if self.isFounder(client) else\
				('op' if self.isOp(client) else\
				'normal'))

	def isMuted(self, client):
		return client.user_id in self.mutelist

	def setTopic(self, client, topic):
		if topic in ('*', None, ""):
			topic = ""
		if (self.topic and topic == self.topic) or (not self.topic and len(topic)==0):
			return
		self.topic = topic
		self.db().setTopic(self, topic, client)

		self.broadcast('CHANNELTOPIC %s %s %s' % (self.name, client.username, topic), set(), 't', None)
		if len(topic)==0:
			self.channelMessage('Topic removed.')
		else:
			self.channelMessage('Topic changed.')
			self.broadcast('CHANNELTOPIC %s %s %s %s' % (self.name, client.username, time.time(), topic), set(), None, 't') # backwards compat
		
	def setFounder(self, client, target):
		self.owner_user_id = target.user_id
		self.db().setFounder(self, target)
		self.channelMessage("<%s> has been set as this %s's founder by <%s>" % (target.username, self.identity, client.username))

	def setAntispam(self, client, val):
		self.antispam = val
		self.db().setAntispam(self, val)
		self.channelMessage('Anti-spam protection was set to %s by <%s>' % (str(val), client.username))

	def setHistory(self, client, val):
		self.store_history = val
		self.db().setHistory(self, val)
		self.channelMessage('History retention was set to %s by <%s>' % (str(val), client.username))

	def setKey(self, client, key):
		self.db().setKey(self, key)
		if key in ('*', None):
			if self.key:
				self.key = None
				self.channelMessage('<%s> removed the password of this %s' % (client.username, self.identity))
		else:
			self.key = key
			self.channelMessage('<%s> set a new password for this %s' % (client.username, self.identity))

	def hasKey(self):
		return self.key not in ('*', None)

	def opUser(self, client, target):
		if target.user_id in self.operators:
			return
		self.operators.add(target.user_id)
		self.db().opUser(self, target)
		self.channelMessage("<%s> has been added to this %s's operator list by <%s>" % (target.username, self.identity, client.username))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].opUser(client, target)

	def deopUser(self, client, target):
		if not target.user_id in self.operators:
			return
		self.operators.remove(target.user_id)
		self.db().deopUser(self, target)
		self.channelMessage("<%s> has been removed from this %s's operator list by <%s>" % (target.username, self.identity, client.username))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].deopUser(client, target)

	def kickUser(self, client, target):
		if hasattr(target, "session_id") and target.session_id in self.users:
			self.removeUser(target)
			self.channelMessage('<%s> has been kicked from this %s by <%s>' % (target.username, self.identity, client.username))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].kickUser(client, target)

	def banUser(self, client, target, expires, reason, duration):
		if target.user_id in self.ban:
			return
		self.kickUser(client, target)
		self.ban[target.user_id] = {'user_id':target.user_id, 'ip_address':target.last_ip, 'expires':expires, 'reason':reason, 'issuer_user_id':client.user_id}
		self.ban_ip[target.last_ip] = self.ban[target.user_id]
		self.db().banUser(self, client, target, expires, reason)
		if hasattr(target, "session_id") and target.session_id in self.users:
			self.channelMessage('<%s> has been removed from this %s by <%s>' % (target.username, self.identity, client.username))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].banUser(client, target, expires, reason, duration)

	def unbanUser(self, client, target):
		if target.user_id in self.ban:
			del self.ban[target.user_id]
		if target.last_ip in self.ban_ip:
			del self.ban_ip[target.last_ip]
		self.db().unbanUser(self, target)

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].unbanUser(client, target)

	def banBridgedUser(self, client, target, expires, reason, duration):
		if target.bridged_id in self.bridged_ban:
			return
		try:
			expires = datetime.now() + duration
		except:
			expires = datetime.max
		self.bridged_ban[target.bridged_id] = {'bridged_id':target.bridged_id, 'expires':expires, 'reason':reason, 'issuer_user_id':client.user_id}
		self.db().banBridgedUser(self, client, target, expires, reason)
		self.removeBridgedUser(client, target)
		if target.bridged_id in self.bridged_users:
			self.channelMessage('<%s> has been removed from this %s by <%s>' % (target.username, self.identity, client.username))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].banBridgedUser(client, target, expires, reason, duration)

	def unbanBridgedUser(self, client, target):
		if not target.bridged_id in self.bridged_ban:
			return
		del self.bridged_ban[target.bridged_id]
		self.db().unbanBridgedUser(self, target)

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].unbanBridgedUser(client, target)

	def getMuteMessage(self, client):
		if self.isMuted(client):
			mute = self.mutelist[client.user_id]
			return 'muted ' + self._root.protocol.pretty_time_delta(mute['expires']-datetime.now())
		return 'not muted'

	def muteUser(self, client, target, expires, reason, duration):
		if target.id in self.mutelist:
			return
		try:
			expires = datetime.now() + duration
		except:
			expires = datetime.max
		self.mutelist[target.user_id] = {'user_id':target.user_id, 'expires':expires, 'reason':reason, 'issuer_user_id':client.user_id}
		self.db().muteUser(self, client, target, expires, reason)
		self.channelMessage('<%s> has been muted by <%s> %s' % (client.username, target.username, self._root.protocol.pretty_time_delta(duration)))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].muteUser(client, target, expires, reason, duration)

	def unmuteUser(self, client, target, reason=None):
		if not target.user_id in self.mutelist:
			return
		del self.mutelist[target.user_id]
		self.db().unmuteUser(self, target)
		self.channelMessage('<%s> has been unmuted by <%s>' % (target.username, client.username))

		for chan in self.forwards:
			if chan in self._root.channels:
				self._root.channels[chan].unmuteUser(client, target, reason)

	def addForward(self, client, channel_to):
		self.forwards.add(channel_to.name)
		self.db().addForward(self, channel_to)

		for user_id in self.operators:
			channel_to.operators.add(user_id)
		for user_id in self.mutelist:
			channel_to.mutelist[user_id] = self.mutelist[user_id]
		for user_id in self.ban:
			channel_to.ban[user_id] = self.ban[user_id]
		for ip in self.ban_ip:
			channel_to.ban_ip[ip] = self.ban_ip[ip]
		for bridged_id in self.bridged_ban:
			channel_to.bridged_ban[bridged_id] = self.bridged_ban[bridged_id]
		self.channelMessage('<%s> added forwarding to #%s' % (client.username, channel_to.name))
		channel_to.channelMessage('<%s> added forwarding to #%s' % (client.username, channel_to.name))

	def removeForward(self, client, channel_to):
		if not channel_to.name in self.forwards:
			return
		self.forwards.remove(channel_to.name)
		self.db().removeForward(self, channel_to)

		self.channelMessage('<%s> removed forwarding to #%s' % (client.username, channel_to.name))
		channel_to.channelMessage('<%s> removed forwarding to #%s' % (client.username, channel_to.name))