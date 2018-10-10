import time

class Channel():
	def __init__(self, root, name):
		self._root = root
		self.identity = 'channel'
		
		# db fields
		self.id = 0 #id 0 is used for all unregistered channels
		self.name = name
		self.key = None 
		self.owner_user_id = None
		self.topic = None
		self.topic_time = None
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

		self.mutelist = {} #user_ids
		self.ban = {} #user_ids
		self.bridged_ban = {} #bridged_ids

		self.chanserv = False

	def broadcast(self, message, ignore=set([])):
		self._root.broadcast(message, self.name, ignore)

	def channelMessage(self, message):
		self.broadcast('CHANNELMESSAGE %s %s' % (self.name, message))

	def register(self, client, target): 
		self.setFounder(client, target)

	def addUser(self, client):
		if client.session_id in self.users:
			return
		self.users.add(client.session_id)
		client.channels.add(self.name)
		client.Send('JOIN %s' % self.name)
		self.broadcast('JOINED %s %s' % (self.name, client.username), set([client.session_id]))
		
		clientlist = ""
		for session_id in self.users:
			if clientlist:
				clientlist += " "
			channeluser = self._root.protocol.clientFromSession(session_id)
			assert(channeluser)
			clientlist += channeluser.username
		client.Send('CLIENTS %s %s' % (self.name, clientlist))

		bridgedClientList = ""
		for bridged_id in self.bridged_users:
			if clientlist:
				clientlist += " "
			bridgedClient = self._root.protocol.bridgedClientFromID(bridged_id)
			assert(bridgedClient)
			bridgedClientList += bridgedClient.username
		if client.compat['u']:
			client.Send('CLIENTSFROM %s %s' % (self.name, bridgedClientList))
		
		topic = self.topic
		if topic:
			if client.compat['et']:
				topictime = int(topic['time'])
			else:
				topictime = int(topic['time'])*1000
			try:
				top = topic['text']
			except:
				top = "Invalid unicode-encoding (should be utf-8)"
				logging.info("%s for channel topic: %s" %(top, self.name))
			client.Send('CHANNELTOPIC %s %s %s %s'%(self.name, topic['user'], topictime, top))
		elif client.compat['et']: # supports sendEmptyTopic
			client.Send('NOCHANNELTOPIC %s' % self.name)

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
		client.Send('LEFT %s %s' % (self.name, client.username))
	
	def addBridgedUser(self, client, bridgedClient):
		bridged_id = bridgedClient.bridged_id
		if bridged_id in self.bridged_users:
			return
		self.bridged_users.add(bridged_id)
		bridgedClient.channels.add(self.name)
		self.broadcast('JOINEDFROM %s %s' % (self.name, bridgedClient.username))
	
	def removeBridgedUser(self, client, bridgedClient, reason=None):
		bridged_id = bridgedClient.bridged_id
		if not bridged_id in self.bridged_users:			
			return
		self.bridged_users.remove(bridged_id)
		bridgedClient.channels.remove(self.name)
		if reason and len(reason) > 0:
			self.broadcast('LEFTFROM %s %s %s' % (self.name, bridgedClient.username, reason))
		else:
			self.broadcast('LEFTFROM %s %s' % (self.name, bridgedClient.username))
		
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
				self.channelMessage('<%s> removed the password of this %s' % (client.username, self.identity))
		else:
			self.key = key
			self.channelMessage('<%s> set a new password for this %s' % (client.username, self.identity))

	def hasKey(self):
		return not key in ('*', None)
		
	def setFounder(self, client, target):
		if not target:
			return
		self.owner_user_id = target.user_id
		self.channelMessage("<%s> has been set as this %s's founder by <%s>" % (target.username, self.identity, client.username))

	def opUser(self, client, target):
		if not target:
			return
		if target.user_id in self.operators:
			return
		self.operators.add(target.user_id)
		self.channelMessage("<%s> has been added to this %s's operator list by <%s>" % (target.username, self.identity, client.username))

	def deopUser(self, client, target):
		if not target:
			return
		if not target.user_id in self.operators:
			return
		self.operators.remove(target.user_id)
		self.channelMessage("<%s> has been removed from this %s's operator list by <%s>" % (target.username, self.identity, client.username))

	def banUser(self, client, target, reason=''):
		if self.isFounder(target): return
		if not target:
			 return
		if not target.user_id in self.ban:
			return
		self.ban[target.user_id] = reason
		self.removeUser(client, target, reason)
		self.channelMessage('<%s> has been removed from this %s by <%s>' % (target.username, self.identity, client.username))

	def unbanUser(self, client, target):
		if not target:
			return
		if not target.user_id in self.ban:
			return
		del self.ban[target.user_id]

	def banBridgedUser(self, client, target, reason=''):
		if not target:
			return
		if target.bridged_id in self.bridged_ban:
			return
		self.bridged_ban[target.bridged_id] = reason
		self.removeBridgedUser(client, target)
		self.channelMessage('<%s> has been removed from this channel by <%s>' % (target.username, client.username))
	
	def unbanBridgedUser(self, client, target):
		if not target:
			return
		if not target.bridged_id in self.bridged_ban:
			return
		del self.bridged_ban[target.bridged_id]
	
	def muteUser(self, client, target, duration=0):
		if not target:
			return
		if self.isFounder(target): 
			return
		if client.user_id in self.mutelist:
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

