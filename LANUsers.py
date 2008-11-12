import time

class LANUser:
	def __init__(self):
		self.ingame_time = 0
		self.access = 'user'
		self.last_login = int(time.time())
		self.register_date = int(time.time())
		self.bot = False

class UsersHandler:
	def __init__(self, root):
		self._root = root
		
	def login_user(self, user, password, ip):
		User = LANUser()
		lanadmin = self._root.lanadmin['username']
		if user == lanadmin['username']
			if password == lanadmin['password']:
				User.access = 'admin'
			else: return False, 'Bad username/password'
		return True, User

	def register_user(self, user, password, ip): # need to add better ban checks so it can check if an ip address is banned when registering an account :) << lolwut this is LAN server
		good = user in self._root.usernames
		return good, 'Account was not actually registered - we are in LAN mode ;).'

	def rename_user(self, user, newname):
		good = user in self._root.usernames
		return good, 'Account was not actually renamed - we are in LAN mode ;).'

	def get_registration_date(self, user):
		return False, 'LAN mode and user not logged in.'
