import time

class LANUser:
	def __init__(self):
		self.ingame_time = 0
		self.access = 'user'
		self.bot = False

class UsersHandler:
	def login_user(self, user, password, ip):
		User = LANUser()
		if ip in ('192.168.1.8', '216.7.57.152') or ip.startswith('127.0.'):
			User.access = 'admin'
		return True, User

	def register_user(self, user, password, ip): # need to add better ban checks so it can check if an ip address is banned when registering an account :) << lolwut this is LAN server
		return True, 'Account was not actually registered - we are in LAN mode ;).'

	def rename_user(self, user, newname):
		return True, 'Account was not actually renamed - we are in LAN mode ;).'
