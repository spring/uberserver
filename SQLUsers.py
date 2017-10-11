#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta

from base64 import b64encode as ENCODE_FUNC
from base64 import b64decode as DECODE_FUNC


from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto import Random

PWRD_HASH_ROUNDS = 1024
USR_DB_SALT_SIZE = 16

from BaseClient import BaseClient


try:
	from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, ForeignKey, Boolean, Text, DateTime, ForeignKeyConstraint, UniqueConstraint
	from sqlalchemy.orm import mapper, sessionmaker, relation
	from sqlalchemy.exc import IntegrityError
except ImportError as e:
	print("ERROR: sqlalchemy isn't installed: " + str(e))
	print("ERROR: please install sqlalchemy, on debian the command is sth. like: ")
	print("sudo apt-get install python-sqlalchemy")
	import sys
	sys.exit(1)


metadata = MetaData()
##########################################
users_table = Table('users', metadata,
	Column('id', Integer, primary_key=True),
	Column('username', String(40), unique=True), # unicode
	Column('password', String(64)), # unicode(BASE64(ASCII)) (unicode is added by DB on write)
	Column('randsalt', String(64)), # unicode(BASE64(ASCII)) (unicode is added by DB on write)
	Column('register_date', DateTime),
	Column('last_login', DateTime),
	Column('last_ip', String(15)), # would need update for ipv6
	Column('last_id', String(128)),
	Column('ingame_time', Integer),
	Column('access', String(32)),
	Column('email', String(254)), # http://www.rfc-editor.org/errata_search.php?rfc=3696&eid=1690
	Column('bot', Integer),
	mysql_charset='utf8',
	)

class User(BaseClient):
	def __init__(self, username, password, randsalt, last_ip, access='agreement'):
		self.set_user_pwrd_salt(username, (password, randsalt))

		self.last_login = datetime.now()
		self.register_date = datetime.now()
		self.last_ip = last_ip
		self.ingame_time = 0
		self.bot = 0
		self.access = access # user, moderator, admin, bot, agreement
		self.last_id = 0
		self.email = ""

	def __repr__(self):
		return "<User('%s', '%s')>" % (self.username, self.password)



##########################################
logins_table = Table('logins', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_dbid', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('ip_address', String(15), nullable=False),
	Column('time', DateTime),
	Column('lobby_id', String(128)),
	Column('cpu', Integer),
	Column('local_ip', String(15)), # needs update for ipv6
	Column('country', String(4)),
	Column('end', DateTime),
	Column('user_id', String(128)),
	mysql_charset='utf8',
	)
class Login(object):
	def __init__(self, now, ip_address, lobby_id, user_id, cpu, local_ip, country):
		self.time = now
		self.ip_address = ip_address
		self.lobby_id = lobby_id
		self.user_id = user_id
		self.cpu = cpu
		self.local_ip = local_ip
		self.country = country
		#self.end = 0

	def __repr__(self):
		return "<Login('%s', '%s')>" % (self.ip_address, self.time)
mapper(Login, logins_table)
##########################################
renames_table = Table('renames', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('original', String(40)),
	Column('new', String(40)), # FIXME: not needed
	Column('time', DateTime),
	mysql_charset='utf8',
	)
class Rename(object):
	def __init__(self, original, new):
		self.original = original
		self.new = new
		self.time = datetime.now()

	def __repr__(self):
		return "<Rename('%s' -> '%s')>" % (self.original, self.new)
mapper(Rename, renames_table)
##########################################
ignores_table = Table('ignores', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('ignored_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('reason', String(128)),
	Column('time', DateTime),
	mysql_charset='utf8',
	)
class Ignore(object):
	def __init__(self, user_id, ignored_user_id, reason):
		self.user_id = user_id
		self.ignored_user_id = ignored_user_id
		self.reason = reason
		self.time = datetime.now()

	def __repr__(self):
		return "<Ignore('%s', '%s', '%s', '%s')>" % (self.user_id, self.ignored_user_id, self.reason, self.time)
mapper(Ignore, ignores_table)
##########################################
friends_table = Table('friends', metadata,
	Column('id', Integer, primary_key=True),
	Column('first_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('second_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('time', DateTime),
	mysql_charset='utf8',
	)
class Friend(object):
	def __init__(self, first_user_id, second_user_id):
		self.first_user_id = first_user_id
		self.second_user_id = second_user_id
		self.time = datetime.now()

	def __repr__(self):
		return "<Friends('%s', '%s')>" % self.first_user_id, self.second_user_id
mapper(Friend, friends_table)
##########################################
friendRequests_table = Table('friendRequests', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('friend_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('msg', String(128)),
	Column('time', DateTime),
	mysql_charset='utf8',
	)
class FriendRequest(object):
	def __init__(self, user_id, friend_user_id, msg):
		self.user_id = user_id
		self.friend_user_id = friend_user_id
		self.msg = msg
		self.time = datetime.now()

	def __repr__(self):
		return "<FriendRequest('%s', '%s', '%s')>" % self.user_id, self.friend_user_id, self.msg
mapper(FriendRequest, friendRequests_table)
##########################################
mapper(User, users_table, properties={
	'logins':relation(Login, backref='user', cascade="all, delete, delete-orphan"),
	'renames':relation(Rename, backref='user', cascade="all, delete, delete-orphan"),
	## FIXME: all of these generate "Could not determine join condition between parent/child tables on relation User.XXXX"
	'ignores':relation(Ignore, cascade="all, delete, delete-orphan", foreign_keys=[Ignore.user_id]),
	'friends1':relation(Friend, cascade="all, delete, delete-orphan", foreign_keys=[Friend.first_user_id]),
	'friends2':relation(Friend, cascade="all, delete, delete-orphan", foreign_keys=[Friend.second_user_id]),
	'friend-requests-by-me':relation(FriendRequest, cascade="all, delete, delete-orphan", foreign_keys=[FriendRequest.user_id]),
	'friend-requests-for-me':relation(FriendRequest, cascade="all, delete, delete-orphan", foreign_keys=[FriendRequest.friend_user_id]),
	})

##########################################
channels_table = Table('channels', metadata,
	Column('id', Integer, primary_key=True),
	Column('name', String(40), unique=True),
	Column('key', String(32)),
	Column('owner', String(40)), #FIXME: delete, use owner_userid
	Column('owner_userid', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL')), # user owner id
	Column('topic', Text),
	Column('topic_time', DateTime),
	Column('topic_owner', String(40)), #FIXME: delete, use topic_userid
	Column('topic_userid', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL')), # topic owner id
	Column('antispam', Boolean),
	Column('autokick', String(5)),
	Column('censor', Boolean),
	Column('antishock', Boolean),
	Column('store_history', Boolean),
	mysql_charset='utf8',
	)
class Channel(object):
	def __init__(self, name,  key='', chanserv=False, owner='', topic='', topic_time=None, topic_owner='', antispam=False, admins='', autokick='ban', censor=False, antishock=False, store_history=False):
		self.name = name
		self.key = key
		self.chanserv = chanserv
		self.owner = owner
		self.topic = topic
		self.topic_time = topic_time or datetime.now()
		self.topic_owner = topic_owner
		self.antispam = antispam
		self.admins = admins
		self.autokick = autokick
		self.censor = censor
		self.antishock = antishock
		self.store_history = store_history

	def __repr__(self):
		return "<Channel('%s')>" % self.name
mapper(Channel, channels_table)
##########################################
channelshistory_table = Table('channel_history', metadata,
	Column('id', Integer, primary_key=True),
	Column('channel_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('time', DateTime),
	Column('msg', Text),
	mysql_charset='utf8',
	)
class ChannelHistory(object):
	def __init__(self, channel_id, user_id, msg, time):
		self.channel_id = channel_id
		self.user_id = user_id
		self.time = time
		self.msg = msg

	def __repr__(self):
		return "<ChannelHistory('%s')>" % self.channel_id
mapper(ChannelHistory, channelshistory_table)

##########################################
banip_table = Table('ban_ip', metadata, # server bans
	Column('id', Integer, primary_key=True),
	Column('issuer_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')), # user which set ban
	Column('ip', String(60)), #ip which is banned
	Column('reason', Text),
	Column('end_time', DateTime),
	Column('updated', DateTime),
	mysql_charset='utf8',
	)
class BanIP(object):
	def __init__(self, ip = None, issuer_id = None, reason = "", end_time = None):
		self.issuer_id = issuer_id
		self.ip = ip
		self.reason = reason
		self.end_time = end_time or datetime.now()
		self.updated = datetime.now()
mapper(BanIP, banip_table)
##########################################
banuser_table = Table('ban_user', metadata, # server bans
	Column('id', Integer, primary_key=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')), # user id which is banned
	Column('issuer_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')), # user which set ban
	Column('reason', Text),
	Column('end_time', DateTime),
	Column('updated', DateTime),
	mysql_charset='utf8',
	)
class BanUser(object):
	def __init__(self, user_id = None, issuer_id = None, reason = "", end_time = None):
		self.user_id = user_id
		self.issuer_id = issuer_id
		self.reason = reason
		self.end_time = end_time or datetime.now()
		self.updated = datetime.now()
mapper(BanUser, banuser_table)
##########################################

#metadata.create_all(engine)



class OfflineClient(BaseClient):
	def __init__(self, sqluser):
		self.set_user_pwrd_salt(sqluser.username, (sqluser.password, sqluser.randsalt))
		self.id = sqluser.id
		self.ingame_time = sqluser.ingame_time
		self.bot = sqluser.bot
		self.last_login = sqluser.last_login
		self.register_date = sqluser.register_date
		self.last_id = sqluser.last_id
		self.access = sqluser.access
		self.email = sqluser.email



class UsersHandler:
	def __init__(self, root, engine):
		self._root = root
		metadata.create_all(engine)
		self.sessionmaker = sessionmaker(bind=engine, autoflush=True)
		self.session = self.sessionmaker()

	def sess(self):
		if self.session.is_active:
			return self.session
		self.session.rollback()
		return self.session

	def clientFromID(self, db_id):
		entry = self.sess().query(User).filter(User.id==db_id).first()
		if not entry: return None
		return OfflineClient(entry)
	
	def clientFromUsername(self, username):
		entry = self.sess().query(User).filter(User.username==username).first()
		if not entry: return None
		return OfflineClient(entry)


	def convert_legacy_user_pwrd(self, session, db_user, password):
		assert(db_user != None)
		assert(len(db_user.randsalt) == 0)

		## in a secure session, so password was only base64-encoded
		## by client and we must apply B64ENCODE(MD5(B64DECODE(..)))
		## to it first
		legacy_pwrd = password.encode("utf-8")
		legacy_pwrd = DECODE_FUNC(legacy_pwrd)
		legacy_pwrd = MD5.new(legacy_pwrd)
		legacy_pwrd = ENCODE_FUNC(legacy_pwrd.digest())
		legacy_pwrd = legacy_pwrd.decode("utf-8")

		## check if a legacy LOGIN would succeed with given password
		if (not self.legacy_test_user_pwrd(db_user, legacy_pwrd)):
			return False

		## commit new-style password(-hash) and salt to DB
		db_user.set_pwrd_salt(self.gen_user_pwrd_hash_and_salt(password))
		session.commit()

		assert(not db_user.has_legacy_password())
		assert(self.secure_test_user_pwrd(db_user, password))
		return True


	def legacy_update_user_pwrd(self, db_user, password):
		assert(db_user.has_legacy_password())

		db_user.set_pwrd_salt((password, ""))
		self.save_user(db_user)

	def secure_update_user_pwrd(self, db_user, password):
		db_user.set_pwrd_salt(self.gen_user_pwrd_hash_and_salt(password))
		self.save_user(db_user)


	def legacy_test_user_pwrd(self, user_inst, user_pwrd):
		return (user_inst.password == user_pwrd)

	## test LOGIN input <user_pwrd> against DB User instance <user_inst>
	def secure_test_user_pwrd(self, user_inst, user_pwrd, hash_func = SHA256.new):
		user_pwrd = DECODE_FUNC(user_pwrd.encode("utf-8"))
		user_salt = DECODE_FUNC(user_inst.randsalt.encode("utf-8"))
		user_hash = hash_func(user_pwrd + user_salt)

		for i in xrange(PWRD_HASH_ROUNDS):
			user_hash = hash_func(user_hash.digest() + user_salt)

		return (user_inst.password.encode("utf-8") == ENCODE_FUNC(user_hash.digest()))


	## server converts all incoming decrypted messages (including those
	## containing password strings) to unicode --> hash-functions do not
	## like this, so we need to encode them again
	## (values retrieved from DB will also be in unicode)
	def gen_user_pwrd_hash_and_salt(self, user_pass, hash_func = SHA256.new, rand_pool = Random.new()):
		def gen_user_salt(rand_pool, num_salt_bytes = USR_DB_SALT_SIZE):
			return (rand_pool.read(num_salt_bytes))

		def gen_user_hash(user_pwrd, user_salt, hash_func = SHA256_HASH_FUNC):
			assert(type(user_pwrd) == str)
			assert(type(user_salt) == str)

			user_hash = hash_func(user_pwrd + user_salt)

			for i in xrange(PWRD_HASH_ROUNDS):
				user_hash = hash_func(user_hash.digest() + user_salt)

			return (user_hash.digest())

		user_pass = DECODE_FUNC(user_pass.encode("utf-8"))
		user_salt = gen_user_salt(rand_pool)
		user_hash = gen_user_hash(user_pass, user_salt, hash_func)

		assert(type(user_salt) == str)
		assert(type(user_hash) == str)
		return (ENCODE_FUNC(user_hash), ENCODE_FUNC(user_salt))

	
	def check_ban(self, user, ip, userid, now):
		## FIXME: "Error reading from DB in in_LOGIN: <lambda>() takes exactly 2 arguments (3 given)"?
		userban = self.sess().query(BanUser).filter(BanUser.user_id == userid, now <= BanUser.end_time).first()

		if (not userban):
			ipban = self.sess().query(BanIP).filter(BanIP.ip == ip, now <= BanIP.end_time).first()

		if userban: return True, userban
		if ipban: return True, ipban
		return False, ""


	def common_login_user(self, dbuser, session,  username, password, ip, lobby_id, user_id, cpu, local_ip, country):
		if self._root.censor and not self._root.SayHooks._nasty_word_censor(username):
			return False, 'Name failed to pass profanity filter.'

		now = datetime.now()
		banned, dbban = self.check_ban(username, ip, dbuser.id, now)
		good = (not banned)

		if banned:
			timeleft = int((dbban.end_time - now).total_seconds())
			reason = 'You are banned: (%s) ' %(dbban.reason)

			if timeleft > 60 * 60 * 24 * 1000:
				reason += 'forever!'
			elif timeleft > 60 * 60 * 24:
				reason += 'days remaining: %s' % (timeleft / (60 * 60 * 24))
			else:
				reason += 'hours remaining: %s' % (timeleft / (60 * 60))

		dbuser.logins.append(Login(now, ip, lobby_id, user_id, cpu, local_ip, country))
		dbuser.time = now
		dbuser.last_ip = ip
		dbuser.last_id = user_id

		if (good):
			## copy unicode(BASE64(...)) values out of DB, leave them as-is
			user_copy = User(dbuser.username, dbuser.password, dbuser.randsalt, ip, now)
			user_copy.access = dbuser.access
			user_copy.id = dbuser.id
			user_copy.ingame_time = dbuser.ingame_time
			user_copy.bot = dbuser.bot
			user_copy.last_login = dbuser.last_login
			user_copy.register_date = dbuser.register_date
			user_copy.lobby_id = lobby_id
			reason = user_copy

		dbuser.last_login = now # store current time to db but keep last_login in in user_copy
		session.commit()

		return good, reason

	def legacy_login_user(self, username, password, ip, lobby_id, user_id, cpu, local_ip, country):
		assert(type(username) == str)
		assert(type(password) == str)

		## should only ever be one user with each name so we can just grab the first one :)
		## password here is unicode(BASE64(MD5(...))), matches the register_user DB encoding
		dbuser = self.sess().query(User).filter(User.username == username).first()

		if (not dbuser):
			return False, 'Invalid username or password'
		if (not self.legacy_test_user_pwrd(dbuser, password)):
			return False, 'Invalid password'

		return (self.common_login_user(dbuser, self.session,  username, password, ip, lobby_id, user_id, cpu, local_ip, country))

	def secure_login_user(self, username, password, ip, lobby_id, user_id, cpu, local_ip, country):
		assert(type(username) == str)
		assert(type(password) == str)

		db_user = self.sess().query(User).filter(User.username == username).first()

		if (not db_user):
			return False, 'Invalid username'

		## check for the special case of a user first using secure login
		## (meaning his legacy-hashed unsalted password is still present
		## in the database)
		## we can now either convert the password or generate a completely
		## new temporary random string, which is more secure but also more
		## inconvenient (or require users to create new accounts)
		if (db_user.has_legacy_password() and (not self.convert_legacy_user_pwrd(session, db_user, password))):
			return False, "Invalid password (conversion failed)."

		## combine user-supplied password with DB salt
		if (not self.secure_test_user_pwrd(db_user, password)):
			return False, 'Invalid password'

		## closes session
		return (self.common_login_user(db_user, self.session,  username, password, ip, lobby_id, user_id, cpu, local_ip, country))


	def end_session(self, db_id):
		entry = self.sess().query(User).filter(User.id==db_id).first()
		if entry and not entry.logins[-1].end:
			entry.logins[-1].end = datetime.now()
			entry.last_login = datetime.now() # in real its last online / last seen
			self.sess().commit()



	def check_user_name(self, user_name):
		if len(user_name) > 20: return False, 'Username too long'
		if self._root.censor:
			if not self._root.SayHooks._nasty_word_censor(user_name):
				return False, 'Name failed to pass profanity filter.'
		return True, ""


	def common_register_user(self, session, username, password):
		assert(type(username) == str)
		assert(type(password) == str)

		status, reason = self.check_user_name(username)

		if (not status):
			return False, reason

		dbuser = self.sess().query(User).filter(User.username == username).first()

		if (dbuser):
			return False, 'Username already exists.'

		return True, ""

	# TODO: improve, e.g. also check if ip address is banned when registering account
	def legacy_register_user(self, username, password, ip, country):
		status, reason = self.common_register_user(self.session, username, password)

		if (not status):
			return False, reason

		## note: password here is BASE64(MD5(...)) and already in unicode
		entry = User(username, password, "", ip)

		self.sess().add(entry)
		self.sess().commit()
		return True, 'Account registered successfully.'

	def secure_register_user(self, username, password, ip, country):
		status, reason = self.common_register_user(self.session, username, password)

		if (not status):
			return False, reason

		hash_salt = self.gen_user_pwrd_hash_and_salt(password)
		## store the <hash(pwrd + salt), salt> pair in DB
		## (will be converted to unicode automatically)
		entry = User(username, hash_salt[0], hash_salt[1], ip)

		session.add(entry)
		session.commit()
		return True, 'Account registered successfully.'


	def ban_user(self, owner, username, duration, reason):
		entry = self.sess().query(User).filter(User.username==username).first()
		if not entry:
			return "Couldn't ban %s, user doesn't exist" % (username)
		end_time = datetime.now() + timedelta(duration)
		ban = BanUser(entry.id, owner.db_id, reason, end_time)
		self.sess().add(ban)
		self.sess().commit()
		return 'Successfully banned %s for %s days.' % (username, duration)
	
	def unban_user(self, username):
		client = self.clientFromUsername(username)
		if not client:
			return "User %s doesn't exist" % username
		results = self.sess().query(BanUser).filter(BanUser.user_id==client.id)
		if results:
			for result in results:
				self.sess().delete(result)
			self.sess().commit()
			return 'Successfully unbanned %s.' % username
		else:
			return 'No matching bans for %s.' % username

	def ban_ip(self, owner, ip, duration, reason):
		# TODO: add owner field to the database for bans
		end_time = datetime.now() + timedelta(duration)
		ban = BanIP(ip, owner.db_id, reason, end_time)
		self.sess().add(ban)
		self.sess().commit()
		return 'Successfully banned %s for %s days.' % (ip, duration)

	def unban_ip(self, ip):
		results = self.sess().query(BanIP).filter(BanIP.ip==ip)
		if results:
			for result in results:
				self.sess().delete(result)
			self.sess().commit()
			return 'Successfully unbanned %s.' % ip
		else:
			return 'No matching bans for %s.' % ip
	
	def banlistuser(self):
		banlist = []
		for ban in self.sess().query(BanUser, User.id, BanUser.end_time, BanUser.reason, User.username).join(User,BanUser.user_id == User.id ):
			banlist.append({
				'userid': ban.id,
				'username': ban.username,
				'endtime': ban.end_time,
				'reason': ban.reason
			})
		return banlist

	def banlistip(self):
		banlist = []
		for ban in self.sess().query(BanIP):
			banlist.append({
				'userid': ban.ip,
				'endtime': ban.end_time,
				'reason': ban.reason
			})
		return banlist

	def rename_user(self, user, newname):
		if len(newname)>20: return False, 'Username too long'
		if self._root.censor:
			if not self._root.SayHooks._nasty_word_censor(user):
				return False, 'New username failed to pass profanity filter.'
		if not newname == user:
			results = self.sess().query(User).filter(User.username==newname).first()
			if results:
				return False, 'Username already exists.'
		entry = self.sess().query(User).filter(User.username==user).first()
		if not entry: return False, 'You don\'t seem to exist anymore. Contact an admin or moderator.'
		entry.renames.append(Rename(user, newname))
		entry.username = newname
		self.sess().commit()
		# need to iterate through channels and rename junk there...
		# it might actually be a lot easier to use userids in the server... # later.
		return True, 'Account renamed successfully.'

	def save_user(self, obj):
		## assert(isinstance(obj, User) or isinstance(obj, Client))

		entry = self.sess().query(User).filter(User.username==obj.username).first()

		if (entry != None):
			## caller might have changed these!
			entry.set_pwrd_salt((obj.password, obj.randsalt))

			entry.ingame_time = obj.ingame_time
			entry.access = obj.access
			entry.bot = obj.bot
			entry.last_id = obj.last_id
			entry.email = obj.email

		self.sess().commit()
	
	def confirm_agreement(self, client):
		entry = self.sess().query(User).filter(User.username==client.username).first()
		if entry: entry.access = 'user'
		self.sess().commit()
	
	def get_lastlogin(self, username):
		entry = self.sess().query(User).filter(User.username==username).first()
		if entry: return True, entry.last_login
		else: return False, 'User not found.'
	
	def get_registration_date(self, username):
		entry = self.sess().query(User).filter(User.username==username).first()
		if entry and entry.register_date: return True, entry.register_date
		else: return False, 'user or date not found in database'
	
	def get_ingame_time(self, username):
		entry = self.sess().query(User).filter(User.username==username).first()
		if entry: return True, entry.ingame_time
		else: return False, 'user not found in database'
	
	def get_account_access(self, username):
		entry = selfsession.query(User).filter(User.username==username).first()
		if entry:
			return True, entry.access
		else: return False, 'user not found in database'
	
	def find_ip(self, ip):
		results = self.sess().query(User).filter(User.last_ip==ip)
		return results
		
	def get_ip(self, username):
		entry = self.sess().query(User).filter(User.username==username).first()
		if not entry:
			return None
		return entry.last_ip

	def remove_user(self, user):
		entry = self.sess().query(User).filter(User.username==user).first()
		if not entry:
			return False, 'User not found.'
		self.sess().delete(entry)
		self.sess().commit()
		return True, 'Success.'

	def clean_users(self):
		''' delete old user accounts (very likely unused) '''
		now = datetime.now()
		#delete users:
		# which didn't accept aggreement after one day
		self.sess().query(User).filter(User.register_date < now - timedelta(days=1)).filter(User.access == "agreement").delete(synchronize_session=False)

		# which have no ingame time, last login > 30 days and no bot
		self.sess().query(User).filter(User.ingame_time == 0).filter(User.last_login < now - timedelta(days=30)).filter(User.bot == 0).filter(User.access == "user").delete(synchronize_session=False)

		# last login > 3 years
		self.sess().query(User).filter(User.last_login < now - timedelta(days=1095)).delete(synchronize_session=False)

		# old messages > 2 weeks
		self.sess().query(ChannelHistory).filter(ChannelHistory.time < now - timedelta(days=14)).delete(synchronize_session=False)

		self.sess().commit()

	def ignore_user(self, user_id, ignore_user_id, reason=None):
		entry = Ignore(user_id, ignore_user_id, reason)
		self.sess().add(entry)
		self.sess().commit()

	def unignore_user(self, user_id, unignore_user_id):
		entry = self.sess().query(Ignore).filter(Ignore.user_id == user_id).filter(Ignore.ignored_user_id == unignore_user_id).one()
		self.sess().delete(entry)
		self.sess().commit()

	# returns id-s of users who had their ignore removed
	def globally_unignore_user(self, unignore_user_id):
		q = self.sess().query(Ignore).filter(Ignore.ignored_user_id == unignore_user_id)
		userids = [ignore.user_id for ignore in q.all()]
		# could be done in one query + hook, fix if bored
		self.sess().query(Ignore).filter(Ignore.ignored_user_id == unignore_user_id).delete()
		self.sess().commit()
		return userids

	def is_ignored(self, user_id, ignore_user_id):
		exists = self.sess().query(Ignore).filter(Ignore.user_id == user_id).filter(Ignore.ignored_user_id == ignore_user_id).count() > 0
		return exists

	def get_ignore_list(self, user_id):
		users = self.sess().query(Ignore).filter(Ignore.user_id == user_id).all()
		users = [(user.ignored_user_id, user.reason) for user in users]
		return users

	def get_ignored_user_ids(self, user_id):
		user_ids = self.sess().query(Ignore.ignored_user_id).filter(Ignore.user_id == user_id).all()
		user_ids = [user_id for user_id, in user_ids]
		return user_ids

	def friend_users(self, user_id, friend_user_id):
		entry = Friend(user_id, friend_user_id)
		self.sess().add(entry)
		self.sess().commit()

	def unfriend_users(self, first_user_id, second_user_id):
		self.sess().query(Friend).filter(Friend.first_user_id == first_user_id).filter(Friend.second_user_id == second_user_id).delete()
		self.sess().query(Friend).filter(Friend.second_user_id == first_user_id).filter(Friend.first_user_id == second_user_id).delete()
		self.sess().commit()

	def are_friends(self, first_user_id, second_user_id):
		q1 = self.sess().query(Friend).filter(Friend.first_user_id == first_user_id)
		q2 = self.sess().query(Friend).filter(Friend.second_user_id == second_user_id)
		exists = q1.union(q2).count() > 0
		return exists

	def get_friend_user_ids(self, user_id):
		q1 = self.sess().query(Friend.second_user_id).filter(Friend.first_user_id == user_id)
		q2 = self.sess().query(Friend.first_user_id).filter(Friend.second_user_id == user_id)
		user_ids = q1.union(q2).all()
		user_ids = [user_id for user_id, in user_ids]
		return user_ids

	def has_friend_request(self, user_id, friend_user_id):
		request = self.sess().query(FriendRequest).filter(FriendRequest.user_id == user_id).filter(FriendRequest.friend_user_id == friend_user_id)
		exists = request.count() > 0
		return exists

	def add_friend_request(self, user_id, friend_user_id, msg=None):
		entry = FriendRequest(user_id, friend_user_id, msg)
		self.sess().add(entry)
		self.sess().commit()

	def remove_friend_request(self, user_id, friend_user_id):
		self.sess().query(FriendRequest).filter(FriendRequest.user_id == user_id).filter(FriendRequest.friend_user_id == friend_user_id).delete()
		self.sess().commit()

	# this returns all friend requests sent _to_ user_id
	def get_friend_request_list(self, user_id):
		reqs = self.sess().query(FriendRequest).filter(FriendRequest.friend_user_id == user_id).all()
		users = [(req.user_id, req.msg) for req in reqs]
		return users

	def add_channel_message(self, channel_id, user_id, msg, date = None):
		if date is None:
			date = datetime.now()
		entry = ChannelHistory(channel_id, user_id, msg, date)
		self.sess().add(entry)
		self.sess().commit()

	#returns a list of channel messages since starttime for the specific userid when he is subscribed to the channel
	# [[date, user, msg], [date, user, msg], ...]
	def get_channel_messages(self, user_id, channel_id, starttime):
		reqs = self.sess().query(ChannelHistory, User).filter(ChannelHistory.channel_id == channel_id).filter(ChannelHistory.time >= starttime).filter(ChannelHistory.user_id == User.id).order_by(ChannelHistory.id).all()
		msgs = [(history.time, user.username, history.msg) for history, user in reqs ]
		if len(msgs)>0:
			assert(type(msgs[0][2]) == str)
		return msgs

class ChannelsHandler:
	def __init__(self, root, engine):
		self._root = root
		metadata.create_all(engine)
		self.sessionmaker = sessionmaker(bind=engine, autoflush=True)
		self.session = self.sessionmaker()

	def sess(self):
		if self.session.is_active:
			return self.session
		self.session.rollback()
		return self.session

	def load_channel(self, name):
		entry = self.sess().query(Channel).filter(Channel.name == name).first()
		return entry

	def load_channels(self):
		response = self.sess().query(Channel)
		channels = {}
		for chan in response:
			channels[chan.name] = {
					'id': chan.id,
					'owner':chan.owner,
					'key':chan.key,
					'topic':chan.topic or '',
					'antispam':chan.antispam,
					'admins':[],
					'chanserv': True,
					'store_history': chan.store_history,
				}
		return channels

	def setTopic(self, user, chan, topic):
		entry = self.sess().query(Channel).filter(Channel.name == chan.name).first()
		if entry:
			entry.topic = topic
			entry.topic_time = datetime.now()
			entry.topic_owner = user
			self.sess().commit()

	def setKey(self, chan, key):
		entry = self.sess().query(Channel).filter(Channel.name == chan.name).first()
		if entry:
			entry.key = key
			self.sess().commit()

	def setHistory(self, chan):
		entry = self.sess().query(Channel).filter(Channel.name == chan.name).first()
		if entry:
			entry.store_history = chan.store_history
			self.sess().commit()

	def register(self, channel, target):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		if not entry:
			entry = Channel(channel.name)
			if channel.topic:
				entry.topic = channel.topic['text']
				entry.topic_time =  datetime.fromtimestamp(channel.topic['time'])
				entry.topic_owner = channel.topic['user']
			else:
				entry.topic_time = datetime.now()
			entry.owner = target.username
			self.sess().add(entry)
			self.sess().commit()
			entry = self.sess().query(Channel).filter(Channel.name == channel.name).first() # set db id to runtime object
			channel.id = entry.id

	def unRegister(self, client, channel):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).delete()
		self.sess().commit()

if __name__ == '__main__':
	class root():
		censor = False
		pass

	import sqlalchemy, os
	try: # cleanup old db
		os.remove("test.db")
	except:
		pass
	engine = sqlalchemy.create_engine("sqlite:///test.db", echo=False)
	def _fk_pragma_on_connect(dbapi_con, con_record):
	        dbapi_con.execute('PRAGMA journal_mode = MEMORY')
	        dbapi_con.execute('PRAGMA synchronous = OFF')
	sqlalchemy.event.listen(engine, 'connect', _fk_pragma_on_connect)

	root = root()
	userdb = UsersHandler(root, engine)
	channeldb = ChannelsHandler(root, engine)

	username = u"test"
	channelname = u"testchannel"

	# test save/load user
	userdb.legacy_register_user(username, u"pass", "192.168.1.1", "DE")
	client = userdb.clientFromUsername(username)
	assert(isinstance(client.id, int))

	# test save/load channel
	channel = Channel(channelname)
	channeldb.register(channel, client)
	assert(channel.id > 0)

	# test setHistory
	assert(channel.store_history == False)
	channel.store_history = True
	channeldb.setHistory(channel)
	channel = channeldb.load_channel(channelname)
	assert(channel.store_history == True)


	# test channel message history
	now = datetime.now()
	msg = u'test message %d äöüÄÖÜß ?(?_°)?'
	for i in range(0, 20):
		userdb.add_channel_message(channel.id, client.id, msg % i, now + timedelta(0, i))

	for i in range(0,21):
		msgs = userdb.get_channel_messages(channel.id, client.id, now + timedelta(0, i))
		assert(len(msgs) == 20 - i)
		if (len(msgs) > 0):
			assert(msgs[0][0] == now + timedelta(0, i))
			assert(msgs[0][1] == client.username)
			assert(msgs[0][2] == msg % i)
			assert(type(msgs[0][2]) == str)
	userdb.clean_users()
	print("Tests went ok")


