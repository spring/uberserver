import thread, time

separator = '-'*60

class root:
	def __init__(self):
		self.local_ip = None
		self.online_ip = None
		self.LAN = False
		self.legacy = False
		self.channels = {}
		self.chan_alias = {}
		self.usernames = {}
		self.clients = {}
		self.battles = {}
		self.mapgrades = {}
		self.nextbattle = 0
		self.clienthandlers = []
		self.console_buffer = []
		thread.start_new_thread(self.mute_timer,())
		thread.start_new_thread(self.console_loop,())
	
	def mute_timer(self):
		while 1:
			now = time.time()
			channels = dict(self.channels)
			for channel in channels:
				mutelist = dict(channels[channel]['mutelist'])
				for user in mutelist:
					expiretime = mutelist[user]
					if 0 <= expiretime and expiretime < now:
						del self.channels[channel]['mutelist'][user]
						self.broadcast('CHANNELMESSAGE %s <%s> has been unmuted (mute expired).'%(channel, user))
			time.sleep(1)

	def error(self, error):
		self.console_write('%s\n%s\n%s'%(separator,error,separator))

	def console_write(self, lines):
		if type(lines) == str:
			lines = lines.split('\n')
		elif not type(lines) == list:
			lines = ['Failed to print lines of type %s'%type(lines)]
		self.console_buffer += lines

	def console_loop(self):
		while True:
			if self.console_buffer:
				print self.console_buffer.pop(0)
			else:
				time.sleep(0.1)
		
	def broadcast(self, msg, chan=None, ignore=[]):
		if type(ignore) == str:
			ignore = [ignore]
		if chan in self.channels:
			if 'users' in self.channels[chan]:
				if len(self.channels[chan]['users']) > 0:
					users = list(self.channels[chan]['users'])
					for user in users:
						if user in self.usernames and not user in ignore:
							try:
								self.clients[self.usernames[user]].Send(msg)
							except KeyError: pass # user was removed
		else:
			users = dict(self.usernames)
			for user in users:
				if not user in ignore:
					try:
						self.clients[self.usernames[user]].Send(msg)
					except KeyError: pass # user was removed

	def broadcast_battle(self, msg, battle_id, ignore=[]):
		if type(ignore) == str:
			ignore = [ignore]
		if battle_id in self.battles:
			if 'users' in self.battles[battle_id]:
				users = dict(self.battles[battle_id]['users'])
				for user in users:
					if user in self.battles[battle_id]['users'] and not user in ignore:
						try:
							self.clients[self.usernames[user]].Send(msg)
						except KeyError: pass # user was removed

	def admin_broadcast(self, msg):
		for client in dict(self.usernames):
			client = self.clients[client]
			if 'admin' in client.accesslevels:
				client.Send('SERVERMSG Admin broadcast: %s'%msg)
