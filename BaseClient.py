class BaseClient(object):
	def __init__(self, username, password, randsalt):
		## password = {MD5(pwrd) for old clients, SHA256(pwrd + salt) for new clients}
		## randsalt = {"" for old clients, random 16-byte binary string for new clients}
		## (here "old" means user was registered over an unencrypted link, without salt)
		self.set_user_pwrd_salt(username, (password, randsalt))

	def has_insecure_password(self):
		return (len(self.randsalt) == 0)


	def set_user_pwrd_salt(self, user_name = "", user_pass_salt = ("", "")):
		assert(type(user_pass_salt) == type(()))

		self.username = user_name
		self.password = user_pass_salt[0]
		self.randsalt = user_pass_salt[1]

	def set_pwrd_salt(self, pwrd_hash_salt):
		assert(type(pwrd_hash_salt) == type(()))

		self.password = pwrd_hash_salt[0]
		self.randsalt = pwrd_hash_salt[1]

