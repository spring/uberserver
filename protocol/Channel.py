import time

class Channel():
	def __init__(self, root, name):
		self.id = 0
		self._root = root
		self.name = name
		self.users = set() # list of session_ids
		self.owner_user_id = None
		self.operators = set()

		self.ban = {}
		self.mutelist = {}

		self.autokick = 'ban'
		self.chanserv = False
		self.antispam = False
		self.censor = False
		self.antishock = False
		self.topic = None
		self.key = None
		self.store_history = False

	def broadcast(self, message, ignore=set([])):
		self._root.broadcast(message, self.name, ignore)

	def channelMessage(self, message):
		self.broadcast('CHANNELMESSAGE %s %s' % (self.name, message))

	def register(self, client, owner_user_id): # fixme: unused?
		self.owner_user_id = owner_user_id

	def addUser(self, client):
		if client.session_id in self.users:
			return
		self.users.add(client.session_id)
		self.broadcast('JOINED %s %s' % (self.name, client.username), set([client.session_id]))

	def removeUser(self, client, reason=None):

		if self.name in client.channels:
			client.channels.remove(self.name)

		if not client.session_id in self.users:
			return
		self.users.remove(client.session_id)

		if reason and len(reason) > 0:
			self.broadcast('LEFT %s %s %s' % (self.name, client.username, reason))
		else:
			self.broadcast('LEFT %s %s' % (self.name, client.username))

	def isAdmin(self, client):
		return client and ('admin' in client.accesslevels)

	def isMod(self, client):
		return client and (('mod' in client.accesslevels) or self.isAdmin(client))

	def isFounder(self, client):
		return client and ((client.user_id == self.owner_user_id) or self.isMod(client))

	def isOp(self, client):
		return client and ((client.user_id in self.operators) or self.isFounder(client))

	def getAccess(self, client): # return client's security clearance
		return 'mod' if self.isMod(client) else\
				('founder' if self.isFounder(client) else\
				('op' if self.isOp(client) else\
				'normal'))

	def isMuted(self, client):
		return client.user_id in self.mutelist

	def getMuteMessage(self, client):
		if self.isMuted(client):
			m = self.mutelist[client.user_id]
			if m['expires'] == 0:
				return 'muted forever'
			else:
				 # TODO: move format_time, bin2dec, etc to a utilities class or module
				return 'muted for the next %s.' % (self._root.protocol._time_until(m['expires']))
		else:
			return 'not muted'

	def setTopic(self, client, topic):
		self.topic = topic

		if topic in ('*', None):
			if self.topic:
				self.channelMessage('Topic disabled.')
				topicdict = {}
		else:
			self.channelMessage('Topic changed.')
			topicdict = {'user':client.username, 'text':topic, 'time':time.time()}
			self.broadcast('CHANNELTOPIC %s %s %s %s'%(self.name, client.username, topicdict['time'], topic))
		self.topic = topicdict

	def setKey(self, client, key):
		if key in ('*', None):
			if self.key:
				self.key = None
				self.channelMessage('<%s> unlocked this channel' % client.username)
		else:
			self.key = key
			self.channelMessage('<%s> locked this channel with a password' % client.username)

	def setFounder(self, client, target):
		if not target:
			return
		self.owner_user_id = target.user_id
		self.channelMessage("<%s> has just been set as this channel's founder by <%s>" % (target.username, client.username))

	def opUser(self, client, target):
		if not target:
			return
		if target.user_id in self.operators:
			return
		self.operators.add(target.user_id)
		self.channelMessage("<%s> has just been added to this channel's operator list by <%s>" % (target.username, client.username))

	def deopUser(self, client, target):
		if not target:
			return
		if not target.user_id in self.operators:
			return
		self.operators.remove(target.user_id)
		self.channelMessage("<%s> has just been removed from this channel's operator list by <%s>" % (target.username, client.username))

	def banUser(self, client, target, reason=''):
		if self.isFounder(target): return
		if not target:
			 return
		if not target.user_id in self.ban:
			return
		self.ban[target.user_id] = reason
		self.kickUser(client, target, reason)
		self.channelMessage('<%s> has been banned from this channel by <%s>' % (target.username, client.username))

	def unbanUser(self, client, target):
		if not target:
			return
		if not target.user_id in self.ban:
			return
		del self.ban[target.user_id]
		self.channelMessage('<%s> has been unbanned from this channel by <%s>' % (target.username, client.username))


	def muteUser(self, client, target, duration=0):
		if not target:
			return
		if self.isFounder(target): 
			return
		if client.db_id in self.mutelist:
			return
		try:
			duration = float(duration)
		except:
			duration = 0
		if duration < 1:
			duration = 0
			self.channelMessage('<%s> has muted <%s>' % (client.username, target.username))
		else:
			self.channelMessage('<%s> has muted <%s> for %s minutes' % (client.username, target.username, duration))				
			duration = duration * 60 #convert to seconds
			duration = time.time() + duration
		self.mutelist[target.user_id] = {'expires':duration }

	def unmuteUser(self, client, target):
		if not target:
			return
		if not target.user_id in self.mutelist:
			return
		del self.mutelist[target.user_id]
		self.channelMessage('<%s> has unmuted <%s>' % (client.username, target.username))

