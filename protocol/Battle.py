from Channel import Channel

class Battle(Channel):
	def __init__(self, root, name):

		Channel.__init__(self, root, name)
		self.identity = 'battle'

		# battle
		self.battle_id = None #FIXME: it would be great to remove this and use battle.name to identify battles, but it causes a big change to protocol -> wait for #58
		self.host = None
		self.type = ''
		self.natType = ''
		self.port = 0

		self.title = ''
		self.map = ''
		self.maphash = None
		self.modname = ''
		self.hashcode = None
		self.engine = ''
		self.version = ''

		self.rank = 0
		self.maxplayers = 0
		self.spectators = 0 # duplicated info?
		self.locked = False

		self.pending_users = set() # users who asked to join, waiting for hosts response

		self.bots = {}
		self.script_tags = {}
		self.startrects = {}
		self.disabled_units = []

		self.replay_script = {} #FIXME: inaccessible via protocol
		self.replay = False
		self.sending_replay_script = False


	def joinBattle(self, client):
		# client joins battle + notifies others
		if 'u' in client.compat:
			client.Send('JOINBATTLE %s %s %s' % (self.battle_id, self.hashcode, self.name))
			self.addUser(client) # join the battles channel
		else:
			# legacy clients without 'u' -- these are in the __battle__ channel from servers point of view, but are not told about it!
			client.Send('JOINBATTLE %s %s' % (self.battle_id, self.hashcode))
			self.users.add(client.session_id)
			client.channels.add(self.name)

		scriptPassword = client.scriptPassword
		host = self._root.protocol.clientFromSession(self.host)
		if scriptPassword and host.compat['sp']:
			if client!=host:
				host.Send('JOINEDBATTLE %s %s %s' % (self.battle_id, client.username, scriptPassword))
				client.Send('JOINEDBATTLE %s %s %s' % (self.battle_id, client.username, scriptPassword))
				self._root.broadcast('JOINEDBATTLE %s %s' % (self.battle_id, client.username), ignore=set([self.host, client.session_id])) 
		else:
			if client!=host:
				host.Send('JOINEDBATTLE %s %s' % (self.battle_id, client.username))
				client.Send('JOINEDBATTLE %s %s' % (self.battle_id, client.username))
				self._root.broadcast('JOINEDBATTLE %s %s' % (self.battle_id, client.username), ignore=set([self.host, client.session_id])) 

		scripttags = []
		for tag, val in self.script_tags.items():
			scripttags.append('%s=%s'%(tag, val))
		client.Send('SETSCRIPTTAGS %s'%'\t'.join(scripttags))
		if self.disabled_units:
			client.Send('DISABLEUNITS %s' % ' '.join(self.disabled_units))

		if self.natType > 0:
			if battle.host == client.session_id:
				raise NameError('%s is having an identity crisis' % (client.name))
			if client.udpport:
				self._root.usernames[host].Send('CLIENTIPPORT %s %s %s' % (username, client.ip_address, client.udpport))

		specs = 0
		for sessionid in self.users:
			battle_client = self._root.protocol.clientFromSession(sessionid)
			if battle_client and battle_client.battlestatus['mode'] == '0':
				specs += 1
			battlestatus = self.calc_battlestatus(battle_client)
			client.Send('CLIENTBATTLESTATUS %s %s %s' % (battle_client.username, battlestatus, battle_client.teamcolor))

		for iter in self.bots:
			bot = self.bots[iter]
			client.Send('ADDBOT %s %s' % (self.battle_id, iter)+' %(owner)s %(battlestatus)s %(teamcolor)s %(AIDLL)s' % (bot))

		for allyno in self.startrects:
			rect = self.startrects[allyno]
			client.Send('ADDSTARTRECT %s' % (allyno)+' %(left)s %(top)s %(right)s %(bottom)s' % (rect))

		client.battlestatus = {'ready':'0', 'id':'0000', 'ally':'0000', 'mode':'0', 'sync':'00', 'side':'00', 'handicap':'0000000'}
		client.teamcolor = '0'
		client.current_battle = self.battle_id
		client.Send('REQUESTBATTLESTATUS')

	def leaveBattle(self, client):
		if 'u' in client.compat:
			self.removeUser(client)
		else:
			self.users.remove(client.session_id)
			if self.name in client.channels:
				client.channels.remove(self.name)
			
		client.scriptPassword = None
		client.current_battle = None
		client.hostport = None

		for bot in list(client.battle_bots):
			del client.battle_bots[bot]
			if bot in self.bots:
				del self.bots[bot]
				self._root.broadcast_battle('REMOVEBOT %s %s' % (self.battle_id, bot), self.battle_id)
		self._root.broadcast('LEFTBATTLE %s %s'%(self.battle_id, client.username))
		if client.session_id == self.host:
			return

		oldspecs = self.spectators
		specs = 0
		for session_id in self.users:
			user = self._root.protocol.clientFromSession(session_id)
			if user and user.battlestatus['mode'] == '0':
				specs += 1
		self.spectators = specs
		if oldspecs != specs:
			self._root.broadcast('UPDATEBATTLEINFO %s %i %i %s %s' % (self.battle_id, self.spectators, self.locked, self.maphash, self.map))

	def calc_battlestatus(self, client):
		battlestatus = client.battlestatus
		status = self._root.protocol._bin2dec('0000%s%s0000%s%s%s%s%s0'%(battlestatus['side'],
											battlestatus['sync'], battlestatus['handicap'],
											battlestatus['mode'], battlestatus['ally'],
											battlestatus['id'], battlestatus['ready']))
		return status


	def kickUser(self, client, target):
		super().kickUser(self, client, target)
		host = self._root.protocol.clientFromSession(self.host)
		host.send("KICKFROMBATTLE %s %s" % (self.battle_id, target.username))

	def hasBotflag(self):
		host = self._root.protocol.clientFromSession(self.host)
		return host.bot

	def canChangeSettings(self, client):
		return client.session_id == self.host

	def setKey():
		return #todo: currently there is no way to inform clients when a new channel/battle key is set/unset
	def passworded(self):
		return 0 if self.key in ('*', None) else 1

