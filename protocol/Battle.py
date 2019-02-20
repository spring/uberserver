from Channel import Channel

class Battle(Channel):
	def __init__(self, root, name):

		Channel.__init__(self, root, name)
		self.__init__Battle__(root, name)
		
	def __init__Battle__(self, root, name):
		self.identity = 'battle'
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
		else:
			client.Send('JOINBATTLE %s %s' % (self.battle_id, self.hashcode))
		self.addUser(client)

		host = self._root.protocol.clientFromSession(self.host)
		if client!=host:
			self._root.broadcast('JOINEDBATTLE %s %s' % (self.battle_id, client.username), ignore=set([self.host, client.session_id])) 
			scriptPassword = client.scriptPassword
			if scriptPassword and 'sp' in host.compat:
				host.Send('JOINEDBATTLE %s %s %s' % (self.battle_id, client.username, scriptPassword))
				client.Send('JOINEDBATTLE %s %s %s' % (self.battle_id, client.username, scriptPassword))
			else:
				host.Send('JOINEDBATTLE %s %s' % (self.battle_id, client.username))
				client.Send('JOINEDBATTLE %s %s' % (self.battle_id, client.username))

		scripttags = []
		for tag, val in self.script_tags.items():
			scripttags.append('%s=%s'%(tag, val))
		client.Send('SETSCRIPTTAGS %s'%'\t'.join(scripttags))
		if self.disabled_units:
			client.Send('DISABLEUNITS %s' % ' '.join(self.disabled_units))

		if self.natType > 0:
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
		# client leaves a battle + notifies others
		self.removeUser(client)
			
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
			return #safety

		oldspecs = self.spectators
		specs = 0
		for session_id in self.users:
			user = self._root.protocol.clientFromSession(session_id)
			if user and user.battlestatus['mode'] == '0':
				specs += 1
		self.spectators = specs
		if oldspecs != specs:
			self._root.broadcast('UPDATEBATTLEINFO %s %i %i %s %s' % (self.battle_id, self.spectators, self.locked, self.maphash, self.map))

	def removeBattle(self):
		# remove all users from channel, announce battle is closed, reset battle part, but leave channel settings intact 
		to_remove = self.bridged_users.copy()
		for bridged_id in to_remove:
			bridgedClient = self._root.bridgedClientFromID(bridged_id)
			chanserv = self._root.chanserv
			self.removeBridgedUser(self, chanserv, bridgedClient)
		to_remove = self.users.copy()
		for session_id in to_remove:
			client = self._root.clientFromSession(session_id)
			client.scriptPassword = None
			client.current_battle = None
			client.hostport = None
			client.battle_bots = {}
			if client.username=="ChanServ":
				continue
			self.removeUser(client)
		self._root.protocol.broadcast_RemoveBattle(self)
		self.__init__Battle__(self._root, self.name)		
			
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

