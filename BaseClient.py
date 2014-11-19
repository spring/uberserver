class BaseClient(object):
	def __init__(self, username, password, randsalt):
		## password = {MD5(pwrd) for old clients, SHA256(pwrd + salt) for new clients}
		## randsalt = {"" for old clients, random 16-byte binary string for new clients}
		## (here "old" means user was registered over an unencrypted link, without salt)
		self.set_user_pwrd_salt(username, (password, randsalt))

		## AES cipher used for encrypted protocol communication
		## (obviously with a different instance and key for each
		## connected client)
		self.aes_cipher_obj = None

	def set_aes_cipher_obj(self, obj):
		if (self.aes_cipher_obj != None):
			del self.aes_cipher_obj
		self.aes_cipher_obj = obj

	def get_aes_cipher_obj(self):
		return self.aes_cipher_obj


	## NOTE:
	##   only for in-memory clients, not DB User instances
	##   when true, aes_cipher_obj always contains a valid
	##   key
	def use_secure_session(self):
		return (self.aes_cipher_obj != None)

	def has_insecure_password(self):
		return (len(self.randsalt) == 0)

	def set_user_pwrd_salt(user_name = "", pwrd_hash_salt = ("", "")):
		assert(type(pwrd_hash_salt) == type(()))

		self.username = user_name
		self.password = user_pass_salt[0]
		self.randsalt = user_pass_salt[1]

	def set_pwrd_salt(self, pwrd_hash_salt):
		assert(type(pwrd_hash_salt) == type(()))

		self.password = pwrd_hash_salt[0]
		self.randsalt = pwrd_hash_salt[1]

