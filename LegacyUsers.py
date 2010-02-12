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
		
		return cls(username.lower(), username, password, ingame_time, bot, access, uid, last_login, last_ip, register_date, country, account_id)
	
	def __init__(self, name, casename, password, ingame_time, bot, access, uid, last_login, last_ip, register_date, country, account_id):
		self.name = name
		self.casename = casename
		self.password = password
		self.ingame_time = ingame_time
		self.bot = bot
		self.access = access
		self.uid = uid
		self.last_login = last_login
		self.last_ip = last_ip
		self.register_date = register_date
		self.country = country
		self.id = account_id
	
	def getAccess(self):
		if self.access in self.levels:
			access = self.levels[self.access]
		else: access = 0
		
		agreement = ('0' if (self.access in ('disabled', 'agreement')) else '1')
		bot = ('1' if self.bot else '0')
		
		return (bot + agreement + dec2bin(self.ingame_time, 20) + dec2bin(access, 3)).lstrip('0') or '0'
	
	def toAccountLine(self):
		return ' '.join((self.casename, self.password, self.getAccess(), self.uid, str(int(self.last_login*1000)), self.last_ip, str(int(self.register_date*1000)), self.country, self.id))