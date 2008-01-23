class root:
	def __init__(self):
		self.channels = {}
		self.usernames = {}
		self.clients = {}
		self.battles = {}
		self.nextbattle = 0
		self.dropped_users = 0

	def broadcast(self, msg, chan=None, ignore=[]):
                if type(ignore) == str:
                        ignore = [ignore]
		if chan in self.channels:
			if 'users' in self.channels[chan]:
				if len(self.channels[chan]['users']) > 0:
					users = dict(self.channels[chan]['users'])
					for user in users:
						if user in self.usernames and not user in ignore:
							self.clients[self.usernames[user]].Send(msg)
		else:
			clients = dict(self.clients)
			for client in clients:
				if not self.clients[client].username in ignore:
					self.clients[client].Send(msg)
		return

	def broadcast_battle(self, msg, battle_id, ignore=[]):
                if type(ignore) == str:
                        ignore = [ignore]
		if battle_id in self.battles:
			if 'users' in self.battles[battle_id]:
				users = dict(self.battles[battle_id]['users'])
				if users > 0:
					for user in users:
						if user in self.usernames and not user in ignore:
							self.clients[self.usernames[user]].Send(msg)
		return
