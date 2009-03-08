import time

class LANUser:
	def __init__(self, user, casename, password, ip):
		self.user = user
		self.casename = casename
		self.ingame_time = 0
		self.access = 'user'
		self.last_login = int(time.time())
		self.register_date = int(time.time())
		self.last_ip = ip
		self.bot = False
		self.hook_chars = ''

class UsersHandler:
	def __init__(self, root):
		self._root = root
		
	def login_user(self, user, password, ip, lobby_id, user_id, cpu, local_ip, country):
		#name = user.lower()
		name = user
		User = LANUser(name, user, password, ip)
		lanadmin = self._root.lanadmin
		#if name == lanadmin['username'].lower():
		#	if password == lanadmin['password']:
		#		User.casename = lanadmin['username']
		#		User.access = 'admin'
		#	else: return False, 'Bad username/password'
		return True, User
	
	def end_session(self, *args, **kwargs): pass

	def register_user(self, user, password, ip): # need to add better ban checks so it can check if an ip address is banned when registering an account :) << lolwut this is LAN server
		good = user in self._root.usernames
		return good, 'Account was not actually registered - we are in LAN mode ;).'

	def rename_user(self, user, newname):
		good = user in self._root.usernames
		return good, 'Account was not actually renamed - we are in LAN mode ;).'

	def get_registration_date(self, user):
		return False, 'LAN mode and user not logged in.'
