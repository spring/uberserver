import time, os

def dec2bin(i, bits=None):
	i = int(i)
	b = ''
	while i > 0:
		j = i & 1
		b = str(j) + b
		i >>= 1
	if bits:
		b = b.rjust(bits,'0')
	return b

class User(object):
	levels = {'admin':3, 'mod':2, 'user':1, 'agreement':1}
	
	@classmethod
	def fromAccountLine(cls, line):
		line = line.split()
		if len(line) < 8: return

		username = line[0]
		password = line[1]
		access = line[2]
		uid = line[3]
		last_login = int(line[4])/1000.0
		last_ip = line[5]
		register_date = int(line[6])/1000.0
		country = line[7]
		# mapgrades = ' '.join(line[8:]) # no longer used
		account_id = line[8]

		accss = int(access, 2)
		
		permissions = int((access[-3:] or '0'), 2)
		ingame_time = int((access[-23:-3] or '0'), 2)
		agreement = (len(access) >= 24 and access[-24] == '1')
		bot = (len(access) >= 25 and access[-25] == '1')

		if permissions and not agreement: access = 'agreement'
		elif permissions == 3: access = 'admin'
		elif permissions == 2: access = 'mod'
		elif permissions == 1: access = 'user'
		else: access = 'disabled'
		
		return cls(username, password, ingame_time, bot, access, uid, last_login, last_ip, register_date, country, account_id)
	
	def __init__(self, username, password, ingame_time, bot, access, uid, last_login, last_ip, register_date, country, account_id):
		self.name = username.lower()
		self.casename = username
		self.password = password
		self.ingame_time = ingame_time
		self.bot = bot
		self.access = access
		self.last_id = uid
		self.last_login = last_login
		self.last_ip = last_ip
		self.register_date = register_date
		self.country = country
		self.id = account_id
		self.hook_chars = ''
	
	def getAccess(self):
		if self.access in self.levels:
			access = self.levels[self.access]
		else: access = 0
		
		agreement = ('0' if (self.access in ('disabled', 'agreement')) else '1')
		bot = ('1' if self.bot else '0')
		
		return (bot + agreement + dec2bin(self.ingame_time, 20) + dec2bin(access, 3)).lstrip('0') or '0'
	
	def toAccountLine(self):
		return ' '.join((self.casename, self.password, self.getAccess(), str(self.last_id), str(int(self.last_login*1000)), self.last_ip, str(int(self.register_date*1000)), self.country, str(self.id)))

class UsersHandler:
	def __init__(self, root, accountstxt):
		self._root = root
		self.accountstxt = accountstxt
		
		self.accounts = {}
		self.idToAccount = {}
		self.lock = None
		self.last_id = 0
		
		self.readAccounts()
	
	def readAccounts(self):
		f = open(self.accountstxt, 'r')
		
		last_id = 0
		line = f.readline().rstrip()
		while line:
			user = User.fromAccountLine(line)
			self.accounts[user.name] = user
			last_id = user.id
			line = f.readline().rstrip()
		
		self.last_id = last_id
		f.close()
	
	def writeAccounts(self):
		f = open(self.accountstxt+'.tmp', 'w')
		
		for user in self.accounts.values():
			f.write(user.toAccountLine()+'\n')
		f.close()
		
		os.rename(self.accountstxt+'.tmp', self.accountstxt)
		
	def clientFromID(self, db_id):
		if db_id in self.idToAccount:
			return self.idToAccount[db_id]
	
	def clientFromUsername(self, username):
		name = username.lower()
		if name in self.accounts:
			return self.accounts[name]
	
	def check_ban(self, user=None, ip=None, userid=None): return
	
	def login_user(self, username, password, ip, lobby_id, user_id, cpu, local_ip, country):
		name = username.lower()
		lanadmin = self._root.lanadmin
		now = int(time.time()*1000)
		if name == lanadmin['username'].lower() and password == lanadmin['password']:
			user = User(lanadmin['username'], password, 0, False, 'admin', None, now, ip, now, country, 0)
			return True, user
		elif name == lanadmin['username'].lower():
			return False, 'Invalid password.'
		
		user = self.clientFromUsername(name)
		if not user:
			return False, 'No user named %s.'%username
		if not password == user.password:
			return False, 'Invalid password.'
		
		user.last_login = now
		user.last_ip = ip
		user.last_id = user_id
		return True, user

	def end_session(self, username): pass
	
	def register_user(self, username, password, ip):
		if len(user)>20: return False, 'Username too long'
		if self._root.censor:
			if not self._root.SayHooks._nasty_word_censor(user):
				return False, 'Name failed to pass profanity filter.'
		
		name = username.lower()
		if name == lanadmin['username'].lower() or name in self.accounts:
			return False, 'Username already exists.'
		
		now = int(time.time()*1000)
		user = User(username, password, 0, None, 'user', now, ip, None, now, country, self.last_id+1)
		self.last_id += 1
		self.accounts[name] = user
		return True, 'Account registered successfully.'
	
	def ban_user(self, username, duration, reason): pass
	def unban_user(self, username): pass
	def banlist(self): return []
	
	def rename_user(self, username, newname):
		if self._root.censor and not self._root.SayHooks._nasty_word_censor(newname):
			return False, 'New username failed to pass profanity filter.'
		user = self.clientFromUsername(username)
		if user:
			name = newname.lower()
			if name in self.accounts:
				return False, 'Username already exists.'
			else:
				user.name = name
				user.casename = newname
				self.accounts[name] = user
				del self.accounts[username.lower()]
				return True, 'Account renamed successfully.'
	
	def save_user(self, client):
		user = self.clientFromUsername(client.username)
		if user:
			user.ingame_time = client.ingame_time
			user.access = client.access
			user.bot = client.bot
			# user.hook_chars = client.hook_chars # not saved to accounts.txt
	
	def confirm_agreement(self, client):
		user = self.clientFromUsername(client.username)
		if user:
			self.accounts[user.name].access = 'user'
	
	def get_lastlogin(self, username):
		user = self.clientFromUsername(client.username)
		if user:
			return True, user.last_login
		else:
			return False, 'User not found.'
	
	def get_registration_date(self, username):
		user = self.clientFromUsername(client.username)
		if user:
			return True, user.registration_date
		else:
			return False, 'User not found.'
	
	def get_ingame_time(self, username):
		user = self.clientFromUsername(client.username)
		if user:
			return True, user.ingame_time
		else:
			return False, 'User not found.'
	
	def get_account_info(self, username):
		user = self.clientFromUsername(client.username)
		if user:
			return True, user.toAccountLine()
		else:
			return False, 'User not found.'
	
	def find_ip(self, ip):
		users = []
		if ':' in ip: # IPv6 - needs to account for ::: vs 00, ambiguous notation
			return ['IPv6 not implemented']
		else: # IPv4
			ip = ip.split('.', 3)
			for user in self.accounts:
				user_ip = user.last_ip.split('.', 3)
				for i in xrange(len(ip)):
					if ip[i] != '*' and not ip[i] == user_ip[i]:
						break
				else:
					users.append(user)
		return users
	
	def get_ip(self, username):
		user = self.clientFromUsername(username)
		if user:
			return user.ip
	
	def remove_user(self, username):
		user = self.clientFromUsername(username)
		if user:
			del self.accounts[user]
			if user.id:
				del self.idToAccount[user.id]