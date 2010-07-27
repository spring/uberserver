import time

class LANUser:
	def __init__(self, user, password, ip):
		self.lowername = user.lower()
		self.username = user
		self.ingame_time = 0
		self.access = 'user'
		self.last_login = int(time.time())
		self.register_date = int(time.time())
		self.last_ip = ip
		self.bot = False
		self.hook_chars = ''
		self.id = None

class UsersHandler:
	def __init__(self, root, engine=None):
		self._root = root
	
	def clientFromID(self, db_id):
		return self._root.clientFromID(db_id)
	
	def clientFromUsername(self, username):
		return self._root.clientFromUsername(username)
	
	def login_user(self, user, password, ip, lobby_id, user_id, cpu, local_ip, country):
		User = LANUser(user, password, ip)
		lanadmin = self._root.lanadmin
		if user.lower() == lanadmin['username'].lower():
			if password == lanadmin['password']:
				User.username = lanadmin['username']
				User.access = 'admin'
			else: return False, 'Bad username/password'
		return True, User

	def register_user(self, user, password, ip, country): # need to add better ban checks so it can check if an ip address is banned when registering an account :) << lolwut this is LAN server
		good = user in self._root.usernames
		return good, 'Account was not actually registered - we are in LAN mode ;).'

	def rename_user(self, user, newname):
		good = user in self._root.usernames
		return good, 'Account was not actually renamed - we are in LAN mode ;).'

	def get_registration_date(self, user):
		return False, 'LAN mode and user not logged in.'

	def save_user(self, *args, **kwargs): pass
	def end_session(self, *args, **kwargs): pass
	def get_ingame_time(self, *args, **kwargs):
		return False, None
	
	def get_lastlogin(self, *args, **kwargs):
		return False, None
	
	def get_account_info(self, *args, **kwargs):
		return False, None
	
	def get_account_access(self, *args, **kwargs):
		return False, None
	
	def find_ip(self, *args, **kwargs):
		return False, None
	
	def get_ip(self, *args, **kwargs):
		return False, None
	
	def ban_user(self, *args, **kwargs):
		return False
	
	def unban_user(self, *args, **kwargs):
		return False
	
	def banlist(self, *args, **kwargs):
		return []