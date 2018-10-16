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

	def broadcast(self, message, ignore=set(), flag=None):
		self._root.broadcast(message, self.name, ignore, None, flag)

	def channelMessage(self, message):
		if self.identity == 'battle': #'u' compat
			self.broadcast('CHANNELMESSAGE %s %s' % (self.name, message), set(), 'u')
			return
		self.broadcast('CHANNELMESSAGE %s %s' % (self.name, message)) 

	def register(self, client, target): 
		self.setFounder(client, target)

	def addUser(self, client):
		if client.session_id in self.users:
			return
		self.users.add(client.session_id)
		client.channels.add(self.name)
		client.Send('JOIN %s' % self.name) #superfluous, could deprecate
		self.broadcast('JOINED %s %s' % (self.name, client.username))
		
		clientlist = ""
		for session_id in self.users:
			if clientlist:
				clientlist += " "
			channeluser = self._root.protocol.clientFromSession(session_id)
			assert(channeluser)
			clientlist += channeluser.username
		client.Send('CLIENTS %s %s' % (self.name, clientlist))

		topic = self.topic
		if not topic:
			if client.compat['et']:
				client.Send('NOCHANNELTOPIC %s' % self.name)
			return
			
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

		if not client.compat['u']:
			return
		
		bridgedClientList = ""
		for bridged_id in self.bridged_users:
			if clientlist:
				clientlist += " "
			bridgedClient = self._root.protocol.bridgedClientFromID(bridged_id)
			assert(bridgedClient)
			bridgedClientList += bridgedClient.username
		client.Send('CLIENTSFROM %s %s' % (self.name, bridgedClientList))
			
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
		self.broadcast('JOINEDFROM %s %s' % (self.name, bridgedClient.username), set(), 'u')
	
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

	def getAccess(self, client): # return client's security clearance
		return 'mod' if self.isMod(client) else\
				('founder' if self.isFounder(client) else\
				('op' if self.isOp(client) else\
				'normal'))

	def isMuted(self, client):
		return client.user_id in self.mutelist

	def setTopic(self, client, topic):		
		if self.topic and topic == self.topic['text']:
			return
		if topic in ('*', None):
			self.topic = {}
			self.channelMessage('Topic disabled.')
			return
		topicdict = {'user':client.username, 'text':topic, 'time':time.time()}
		self.topic = topicdict
		self.channelMessage('Topic changed.')
		
		if self.identity == 'battle': #'u' compat
			self.broadcast('CHANNELTOPIC %s %s %s %s'%(self.name, client.username, topicdict['time'], topic), set(), 'u')  
			return
		self.broadcast('CHANNELTOPIC %s %s %s %s'%(self.name, client.username, topicdict['time'], topic), set())  
	
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

	def kickUser(self, client, target):
		if target.user_id in self.operators:
			return
		if not hasattr(target, "session_id") or target.session_id in self.users:
			return
		self.removeUser(client, target)
		self.channelMessage('<%s> has been kicked from this %s by <%s>' % (target.username, self.identity, client.username))
	
	def kickBridgedUser(self, client, target):
		if not target.bridged_id in self.bridged_users:
			return
		self.removeBridgedUser(client, target)
		self.channelMessage('<%s> has been kicked from this %s by <%s>' % (target.username, self.identity, client.username))
	
	def banUser(self, client, target, expires, reason, duration):
		if not target:
			 return
		self.ban[target.user_id] = {'user_id':target.user_id, 'expires':expires, 'reason':reason, 'issuer_user_id':client.user_id}
		self.removeUser(client, target)
		self.channelMessage('<%s> has been removed from this %s by <%s>' % (target.username, self.identity, client.username))

	def unbanUser(self, client, target):
		if not target.user_id in self.ban:
			return
		del self.ban[target.user_id]

	def banBridgedUser(self, client, target, expires, reason, duration):
		if target.bridged_id in self.bridged_ban:
			return
		try: 
			expires = datetime.now() + duration
		except:
			expires = datetime.max
		self.bridged_ban[target.bridged_id] = {'bridged_id':target.bridged_id, 'expires':expires, 'reason':reason, 'issuer_user_id':client.user_id}
		self.removeBridgedUser(client, target)
		self.channelMessage('<%s> has been removed from this channel by <%s>' % (target.username, client.username))
	
	def unbanBridgedUser(self, client, bridged_id): #bridged_id as arg, because we don't save a global register of bridged users
		if not bridged_id in self.bridged_ban:
			return
		del self.bridged_ban[bridged_id]
	
	def getMuteMessage(self, client):
		if self.isMuted(client):
			mute = self.mutelist[client.user_id]
			return 'muted ' + self._root.protocol.pretty_time_delta(mute['expires']-datetime.now())
		return 'not muted'

	def muteUser(self, client, target, expires, reason, duration):
		try: 
			expires = datetime.now() + duration
		except:
			expires = datetime.max
		self.channelMessage('<%s> has been muted by <%s> %s' % (client.username, target.username, self._root.protocol.pretty_time_delta(duration)))				
		self.mutelist[target.user_id] = {'user_id':target.user_id, 'expires':expires, 'reason':reason, 'issuer_user_id':client.user_id}

	def unmuteUser(self, client, target, reason=None):
		if not target.user_id in self.mutelist:
			return
		del self.mutelist[target.user_id]
		if not reason:
			self.channelMessage('<%s> has been unmuted by <%s>' % (target.username, client.username))
			return
		self.channelMessage('<%s> has been unmuted by <%s> (%s)' % (target.username, client.username, reason))

	def list_mutes(self, client):
		client.Send(" -- Mutelist for %s -- " % self.name)
		for user_id in self.mutelist:
			mute = self.mutelist[user_id]
			target = self._root.protocol.clientFromID(user_id)
			if not target:
				continue
			issuer = self._root.protocol.clientFromID(mute.issuer_user_id)
			issuer_name_str = "unknown"
			if issuer:
				issuer_name_str = issuer.name
			client.Send("%s :: %s :: ends %s (%s)" % (target.usernname, mute.reason, mute.expires, issuer_name_str))
		client.Send(" -- End Mutelist -- ")
	