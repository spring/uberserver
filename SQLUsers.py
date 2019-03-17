#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from BaseClient import BaseClient

import time, random, re, hashlib, base64
import logging

import smtplib
from email.mime.text import MIMEText

import _thread as thread

	
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
	def __init__(self, username, password, randsalt, last_ip, email, access='agreement'):
		self.set_user_pwrd_salt(username, (password, randsalt))

		self.last_login = datetime.now()
		self.register_date = datetime.now()
		self.last_ip = last_ip
		self.email = email
		self.ingame_time = 0
		self.bot = 0
		self.access = access # user, moderator, admin, bot, agreement
		self.last_id = 0

	def __repr__(self):
		return "<User('%s', '%s')>" % (self.username, self.password)

##########################################
verifications_table = Table('verifications', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('email', String(254), unique=True),
	Column('code', Integer),
	Column('expiry', DateTime),
	Column('attempts', Integer),
	Column('resends', Integer),
	Column('use_delay', Boolean),
	Column('reason', Text),
	mysql_charset='utf8',
	)
class Verification(object):
	def __init__(self, user_id, email, digits, use_delay, reason):
		self.user_id = user_id
		self.email = email
		assert(digits>=4)
		self.code = random.randint(10**(digits-1),10**(digits)-1)
		self.expiry = datetime.now() + timedelta(days=2)
		self.attempts = 0
		self.resends = 0
		self.use_delay = use_delay
		self.reason = reason

	def __repr__(self):
		return "<Verification('%s', '%s', '%s', '%s', '%s', %i, %i, %r)>" % (self.id, self.user_id, self.email, self.code, self.expiry, self.attempts, self.resends, self.use_delay)
mapper(Verification, verifications_table)

##########################################
logins_table = Table('logins', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_dbid', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('ip_address', String(15), nullable=False),
	Column('time', DateTime),
	Column('lobby_id', String(64)),
	Column('local_ip', String(15)), # needs update for ipv6
	Column('country', String(4)),
	Column('end', DateTime),
	Column('user_id', String(128)),
	mysql_charset='utf8',
	)

class Login(object):
	def __init__(self, now, ip_address, lobby_id, user_id, local_ip, country):
		self.time = now
		self.ip_address = ip_address
		self.lobby_id = lobby_id
		self.user_id = user_id
		self.local_ip = local_ip
		self.country = country

	def __repr__(self):
		return "<Login('%s', '%s')>" % (self.ip_address, self.time)
mapper(Login, logins_table)
##########################################
bridged_users_table = Table('bridged_users', metadata,
	Column('id', Integer, primary_key=True),
	Column('external_id', String(20)),
	Column('location', String(20)),
	Column('external_username', String(20)),
	Column('last_bridged', DateTime),
	UniqueConstraint('external_id', 'location', name='uix_bridged_users_1'),
	UniqueConstraint('external_username', 'location', name='uix_bridged_users_2'),
	mysql_charset='utf8',
	)
class BridgedUser(object):
	def __init__(self, location, external_id, external_username, last_bridged):
		self.external_id = external_id
		self.location = location
		self.external_username = external_username
		self.last_bridged = last_bridged

	def __repr__(self):
		return "<BridgedUser('%s', '%s', '%s', '%s')>" % (self.id, self.external_id, self.location, self.last_bridged)
mapper(BridgedUser, bridged_users_table)
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
	Column('owner_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True),
	Column('topic', Text),
	Column('topic_time', DateTime), #deprecated; todo: remove this
	Column('topic_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True),
	Column('antispam', Boolean),
	Column('autokick', String(5)), #deprecated; todo: remove this
	Column('censor', Boolean),
	Column('antishock', Boolean), #deprecated; todo: remove this
	Column('store_history', Boolean),
	mysql_charset='utf8',
	)
class Channel(object):
	def __init__(self, name):
		self.name = name
		self.key = None
		self.owner_user_id = None
		self.topic = None
		self.topic_time = None
		self.topic_user_id = None
		self.antispam = False
		self.autokick = None
		self.censor = False
		self.antishock = None
		self.store_history = False

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
channelops_table = Table('channel_ops', metadata,
	Column('id', Integer, primary_key=True),
	Column('channel_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	)
class ChannelOp(object):
	def __init__(self, channel_id, user_id):
		self.channel_id = channel_id
		self.user_id = user_id

	def __repr__(self):
		return "<ChannelOp(%s,%s)>" % (self.channel_id, self.user_id)
mapper(ChannelOp, channelops_table)
##########################################
channelbans_table = Table('channel_bans', metadata,
	Column('id', Integer, primary_key=True),
	Column('channel_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('issuer_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('ip_address', String(15)),
	Column('expires', DateTime),
	Column('reason', Text)
	)
class ChannelBan(object):
	def __init__(self, channel_id, issuer_user_id, user_id, ip_address, expires, reason):
		self.channel_id = channel_id
		self.issuer_user_id = issuer_user_id
		self.user_id = user_id
		self.ip_address = ip_address
		self.expires = expires
		self.reason = reason

	def __repr__(self):
		return "<ChannelBan(%s,%s)>" % (self.channel_id, self.user_id)
mapper(ChannelBan, channelbans_table)
##########################################
channelbridgedbans_table = Table('channel_bridged_bans', metadata,
	Column('id', Integer, primary_key=True),
	Column('channel_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('issuer_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True),
	Column('bridged_id', Integer, ForeignKey('bridged_users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('expires', DateTime),
	Column('reason', Text)
	)
class ChannelBridgedBan(object):
	def __init__(self, channel_id, issuer_user_id, bridged_id, expires, reason):
		self.channel_id = channel_id
		self.issuer_user_id = issuer_user_id
		self.bridged_id = bridged_id
		self.expires = expires
		self.reason = reason

	def __repr__(self):
		return "<ChannelBridgedBan(%s,%s)>" % (self.channel_id, self.bridged_id)
mapper(ChannelBridgedBan, channelbridgedbans_table)
##########################################
channelmutes_table = Table('channel_mutes', metadata,
	Column('id', Integer, primary_key=True),
	Column('channel_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('issuer_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True),
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('expires', DateTime),
	Column('reason', Text)
	)
class ChannelMute(object):
	def __init__(self, channel_id, issuer_user_id, user_id, expires, reason):
		self.channel_id = channel_id
		self.issuer_user_id = issuer_user_id
		self.user_id = user_id
		self.expires = expires
		self.reason = reason

	def __repr__(self):
		return "<ChannelMute(%s,%s)>" % (self.channel_id, self.user_id)
mapper(ChannelMute, channelmutes_table)
##########################################
channelforwards_table = Table('channel_forwards', metadata,
	Column('id', Integer, primary_key=True),
	Column('channel_from_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	Column('channel_to_id', Integer, ForeignKey('channels.id', onupdate='CASCADE', ondelete='CASCADE')),
	UniqueConstraint('channel_from_id', 'channel_to_id', name='uix_channelforwards'),
	)
class ChannelForward(object):
	def __init__(self, channel_from_id, channel_to_id):
		self.channel_from_id = channel_from_id
		self.channel_to_id = channel_to_id

	def __repr__(self):
		return "<ChannelForward(%s,%s)>" % (self.channel_id_from, self.channel_id_to)
mapper(ChannelForward, channelforwards_table)
##########################################
ban_table = Table('ban', metadata, # server bans
	Column('id', Integer, primary_key=True),
	Column('issuer_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True), # user which set ban
	Column('user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE')), # user id which is banned (optional)
	Column('ip', String(60)), #ip which is banned (optional)
	Column('email', String(254)), #email which is banned (optional)
	Column('reason', Text),
	Column('end_date', DateTime),
	mysql_charset='utf8',
	)
class Ban(object):
	def __init__(self, issuer_user_id, duration, reason, user_id=None, ip=None, email=None):
		self.issuer_user_id = issuer_user_id
		self.user_id = user_id
		self.ip = ip
		self.email = email
		self.reason = reason
		self.end_date = datetime.now() + timedelta(duration)

	def __repr__(self):
		user_id_str = str(self.user_id)+', ' if self.user_id else ""
		ip_str = self.ip+', ' if self.ip else ""
		email_str = self.email+', ' if self.email else ""
		ban_str = user_id_str + ip_str + email_str
		return "<Ban: %s (%s, %s)>" % (ban_str, self.issuer_user_id, self.end_date)
mapper(Ban, ban_table)
##########################################
blacklisted_email_domain_table = Table('blacklisted_email_domains', metadata, # email domains that can't be used for account verification
	Column('id', Integer, primary_key=True),
	Column('issuer_user_id', Integer, ForeignKey('users.id', onupdate='CASCADE', ondelete='SET NULL'), nullable=True), # user which set ban
	Column('domain', String(254), unique=True),
	Column('reason', Text),
	Column('start_time', DateTime),
	)
class BlacklistedEmailDomain(object):
	def __init__(self, issuer_user_id, domain, reason):
		self.issuer_user_id = issuer_user_id
		self.domain = domain
		self.reason = reason
		self.start_time = datetime.now()

	def __repr__(self):
		return "<Domain: %s (%s, since %s)>" % (self.domain, self.issuer_user_id, self.start_time)
mapper(BlacklistedEmailDomain, blacklisted_email_domain_table)
##########################################

class session_manager():
	# on-demand sessionmaker
	def __init__(self, root, engine):
		self._root = root
		metadata.create_all(engine)
		self.sessionmaker = sessionmaker(bind=engine, autoflush=True)
		self.session = None
	
	def sess(self):
		if not self.session:
			self.session = self.sessionmaker()
		return self.session
		
	# guarded access
	def commit_guard(self):
		if self.session:
			self.session.commit()
	def rollback_guard(self):
		if self.session:
			self.session.rollback()
	def close_guard(self):
		if self.session:
			self.session.close()
			self.session = None

##########################################
			
			
class OfflineClient(BaseClient):
	def __init__(self, sqluser):
		self.set_user_pwrd_salt(sqluser.username, (sqluser.password, sqluser.randsalt))
		self.id = sqluser.id
		self.user_id = sqluser.id
		self.ingame_time = sqluser.ingame_time
		self.bot = sqluser.bot
		self.last_login = sqluser.last_login
		self.register_date = sqluser.register_date
		self.last_id = sqluser.last_id
		self.last_ip = sqluser.last_ip
		self.access = sqluser.access
		self.email = sqluser.email

class UsersHandler:
	def __init__(self, root):
		self._root = root

	def sess(self):
		return self._root.session_manager.sess()

	def clientFromID(self, user_id):
		entry = self.sess().query(User).filter(User.id==user_id).first()
		if not entry: return None
		return OfflineClient(entry)

	def clientFromUsername(self, username):
		entry = self.sess().query(User).filter(User.username==username).first()
		if not entry: return None
		return OfflineClient(entry)

	def legacy_update_user_pwrd(self, db_user, password):
		assert(db_user.has_legacy_password())

		db_user.set_pwrd_salt((password, ""))
		self.save_user(db_user)

	def legacy_test_user_pwrd(self, dbuser, password):
		return (dbuser.password == password)

	def remaining_ban_str(self, dbban, now):
		timeleft = int((dbban.end_date - now).total_seconds())
		remaining = 'less than one hour remaining'
		if timeleft > 60*60*24*900:
			remaining = ''
		elif timeleft > 60*60*24:
			remaining = '%s days remaining' % (int(timeleft / (60 * 60 * 24)))
		elif timeleft > 60*60:
			remaining = '%s hours remaining' % (int(timeleft / (60 * 60)))
		return remaining

	def check_banned(self, username, ip):
		dbuser = self.sess().query(User).filter(User.username == username).first()
		if not dbuser:
			return False, ""
		now = datetime.now()
		dbban = self._root.bandb.check_ban(dbuser.id, ip, dbuser.email, now)
		if dbban and not dbuser.access=='admin':
			reason = 'You are banned: (%s), ' %(dbban.reason)
			reason += self.remaining_ban_str(dbban, now)
			return True, reason
		return False, ""
		
	def login_user(self, username, password, ip, lobby_id, last_id, local_ip, country):
		# should only ever be one user with each name so we can just grab the first one :)
		# password here is unicode(BASE64(MD5(...))), matches the register_user DB encoding
		dbuser = self.sess().query(User).filter(User.username == username).first()
		if (not dbuser):
			return False, 'Invalid username or password'
		if (not self.legacy_test_user_pwrd(dbuser, password)):
			return False, 'Invalid username or password'

		now = datetime.now()
		dbuser.logins.append(Login(now, ip, lobby_id, last_id, local_ip, country))
		dbuser.time = now
		dbuser.last_ip = ip
		dbuser.last_id = last_id

		# copy unicode(BASE64(...)) values out of DB, leave them as-is
		user_copy = User(dbuser.username, dbuser.password, dbuser.randsalt, ip, dbuser.email)
		user_copy.access = dbuser.access
		user_copy.id = dbuser.id
		user_copy.ingame_time = dbuser.ingame_time
		user_copy.bot = dbuser.bot
		user_copy.last_login = dbuser.last_login
		user_copy.last_id = dbuser.last_id
		user_copy.register_date = dbuser.register_date
		user_copy.lobby_id = lobby_id
		reason = user_copy

		dbuser.last_login = now # store current time to db but keep last_login in the copy we send back
		self.sess().commit()

		return True, reason

	def end_session(self, user_id):
		entry = self.sess().query(User).filter(User.id==user_id).first()
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

	def check_register_user(self, username, email=None, ip_address=None):
		assert(type(username) == str)

		status, reason = self.check_user_name(username)
		if not status:
			return False, reason
		dbuser = self.sess().query(User).filter(User.username == username).first()
		if dbuser:
			return False, 'Username already exists.'
		if email:
			dbemail = self.sess().query(User).filter(User.email == email).first()
			if dbemail:
				return False, 'Email address already in use.'
		if ip_address:
			ipban = self._root.bandb.check_ban(None, ip_address)
			if ipban:
				return False, 'Account registration failed: %s' % ipban.reason
		return True, ""

	def register_user(self, username, password, ip, email):
		# note: password here is BASE64(MD5(...)) and already in unicode
		# assume check_register_user was already called
		entry = User(username, password, "", ip, email)

		self.sess().add(entry)
		self.sess().commit()
		return True, 'Account registered successfully.'

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

	def get_user_id_with_email(self, email):
		if email == '':
			return False, 'Email address is blank'
		response = self.sess().query(User).filter(User.email == email)
		dbuser = response.first()
		if not dbuser:
			return False, 'No user with email address %s was found' % email
		for entry in response: # pick oldest, if multiple choices
			if entry.register_date < dbuser.register_date:
				db_user = entry
		return True, dbuser.id

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
		entry = self.session.query(User).filter(User.username==username).first()
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

	def clean(self):
		now = datetime.now()
		#delete users:
		# which didn't accept agreement after one week
		response = self.sess().query(User).filter(User.register_date < now - timedelta(days=7)).filter(User.access == "agreement")
		logging.info("deleting %i users who failed to verify registration", response.count())
		response.delete(synchronize_session=False)

		# which have no ingame time, last login > 30 days, not bot, not mod
		response = self.sess().query(User).filter(User.ingame_time == 0).filter(User.last_login < now - timedelta(days=30)).filter(User.bot == 0).filter(User.access == "user")
		logging.info("deleting %i inactive users with no ingame time", response.count())
		response.delete(synchronize_session=False)

		# last login > 5 years
		self.sess().query(User).filter(User.last_login < now - timedelta(days=1825)).delete(synchronize_session=False)
		logging.info("deleting %i very inactive users", response.count())
		response.delete(synchronize_session=False)

		# old messages > 2 weeks
		self.sess().query(ChannelHistory).filter(ChannelHistory.time < now - timedelta(days=14)).delete(synchronize_session=False)
		logging.info("deleting %i channel history messages", response.count())
		response.delete(synchronize_session=False)

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
		return entry.id

	#returns a list of channel messages since starttime for the specific userid when he is subscribed to the channel
	# [[date, user, msg], [date, user, msg], ...]
	def get_channel_messages(self, user_id, channel_id, lastid):
		reqs = self.sess().query(ChannelHistory.time, ChannelHistory.msg, User.username, ChannelHistory.id).filter(ChannelHistory.channel_id == channel_id).filter(ChannelHistory.id > lastid).join(User, isouter=True).order_by(ChannelHistory.id).all()
		msgs = [(htime, username, msg, id) if username else (htime, 'ChanServ', msg, id) for htime, msg, username, id in reqs ]
		if len(msgs)>0:
			assert(type(msgs[0][2]) == str)
		return msgs

class OfflineBridgedClient():
	def __init__(self, sqluser):
		# db fields
		self.bridged_id = sqluser.id
		self.location = sqluser.location
		self.external_id = sqluser.external_id
		self.external_username = sqluser.external_username
		self.last_bridged = sqluser.last_bridged

		# non-db fields
		self.username = self.external_username + ':' + self.location  
		self.channels = set()
		self.bridge_user_id = None

class BridgedUsersHandler:
	def __init__(self, root):
		self._root = root

	def sess(self):
		return self._root.session_manager.sess()

	def bridgedClient(self, location, external_id):
		entry = self.sess().query(BridgedUser).filter(BridgedUser.external_id == external_id).filter(BridgedUser.location == location).first()
		if not entry:
			return
		return OfflineBridgedClient(entry)

	def bridgedClientFromID(self, bridged_id):
		entry = self.sess().query(BridgedUser).filter(BridgedUser.id == bridged_id).first()
		if not entry:
			return
		return OfflineBridgedClient(entry)

	def bridgedClientFromUsername(self, username):
		external_username,location = username.split(':',1)
		if not external_username or not location:
			return
		entry = self.sess().query(BridgedUser).filter(BridgedUser.external_username == external_username).filter(BridgedUser.location == location).first()
		if not entry:
			return
		return OfflineBridgedClient(entry)

	def new_bridge_user(self, location, external_id, external_username):
		now = datetime.now()
		entry = BridgedUser(location, external_id, external_username, now)
		self.sess().add(entry)
		self.sess().commit()
		bridgedUser = self.sess().query(BridgedUser).filter(BridgedUser.external_id == external_id).filter(BridgedUser.location == location).first()
		return entry

	def bridge_user(self, location, external_id, external_username):
		bridgedUser = self.sess().query(BridgedUser).filter(BridgedUser.external_id == external_id).filter(BridgedUser.location == location).first()
		entry = self.sess().query(BridgedUser).filter(BridgedUser.external_username == external_username).filter(BridgedUser.location == location).first()
		if (entry and entry.external_id != external_id):
			return False, "Another bridged user (external_id '%s') with location '%s' is currently associated to the external username '%s'" % (entry.external_id, location, external_username)
		if not bridgedUser:
			entry = self.new_bridge_user(location, external_id, external_username)
			return True, OfflineBridgedClient(entry)
		bridgedUser.external_username = external_username
		bridgedUser.last_bridged = datetime.now()
		self.sess().commit()
		return True, OfflineBridgedClient(bridgedUser)

	def clean(self):
		# remove any bridged user that wasn't seen for 30 days and isn't banned from any channels
		bridge_bans = self.sess().query(ChannelBridgedBan.bridged_id).distinct()
		ignore_ids = set(b.bridged_id for b in bridge_bans)		
		now = datetime.now()
		response = self.sess().query(BridgedUser).filter(BridgedUser.last_bridged < now - timedelta(days=30)).filter(not BridgedUser.id in ignore_ids)
		logging.info("deleting %i inactive bridged users", response.count())
		response.delete(synchronize_session=False)
		self.sess().commit()

class BansHandler:
	def __init__(self, root):
		self._root = root

	def sess(self):
		return self._root.session_manager.sess()

	def check_ban(self, user_id=None, ip=None, email=None, now=None):
		# check if any of the args are currently banned
		# fixme: its probably possible to do this with a single db command!
		if not now:
			now = datetime.now()
		if user_id:
			userban = self.sess().query(Ban).filter(Ban.user_id == user_id, now <= Ban.end_date).first()
			if userban:
				return userban
		if ip:
			ipban = self.sess().query(Ban).filter(Ban.ip == ip, now <= Ban.end_date).first()
			if ipban:
				return ipban
		if email:
			emailban = self.sess().query(Ban).filter(Ban.email == email, now <= Ban.end_date).first()
			if emailban:
				return emailban
		return None

	def ban(self, issuer, duration, reason, username):
		# ban the user_id, current ip, and current email, of the target username (as a single ban)
		try:
			duration = float(duration)
		except:
			return False, 'Duration must be a float, cannot convert %s' % duration

		entry = self.sess().query(User).filter(User.username==username).first()
		if not entry:
			return False, "Unable to ban %s, user doesn't exist" % username
		ban = Ban(issuer.user_id, duration, reason, entry.id, entry.last_ip, entry.email)
		self.sess().add(ban)
		self.sess().commit()
		return True, 'Successfully banned %s, %s, %s for %s days.' % (username, entry.last_ip, entry.email, duration)

	def ban_specific(self, issuer, duration, reason, arg):
		# arg might be username, ip or email; ban it
		try:
			duration = float(duration)
		except:
			return False, 'Duration must be a float, cannot convert %s' % duration

		email_match,_ = self._root.verificationdb.valid_email_addr(arg)
		ip_match = re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", arg)
		entry = self.sess().query(User).filter(User.username==arg).first()
		if email_match:
			ban = Ban(issuer.user_id, duration, reason, None, None, arg)
		elif ip_match:
			ban = Ban(issuer.user_id, duration, reason, None, arg, None)
		elif entry:
			ban = Ban(issuer.user_id, duration, reason, entry.id, None, None)
		else:
			return False, "Unable to match '%s' to username/ip/email" % arg
		self.sess().add(ban)
		self.sess().commit()
		return True, 'Successfully banned %s for %s days' % (arg, duration)

	def unban(self, issuer, arg):
		# arg might be username, ip or email; remove all associated bans
		email_match,_ = self._root.verificationdb.valid_email_addr(arg)
		ip_match = re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", arg)
		entry = self.sess().query(User).filter(User.username==arg).first()
		if not (email_match or ip_match or entry):
			return False, "Unable to match '%s' to username/ip/email" % arg
		result = []
		n_unban = 0
		if email_match:
			results = self.sess().query(Ban).filter(Ban.email==arg)
			for result in results:
				self.sess().delete(result)
				n_unban += 1
		if ip_match:
			results = self.sess().query(Ban).filter(Ban.ip==arg)
			for result in results:
				self.sess().delete(result)
				n_unban += 1
		if entry:
			results = self.sess().query(Ban).filter(Ban.user_id==entry.id)
			for result in results:
				self.sess().delete(result)
				n_unban += 1
		self.sess().commit()
		if n_unban>0:
			return True, 'Successfully removed %s bans relating to %s' % (n_unban, arg)
		else:
			return False, 'No matching bans for %s' % arg

	def check_blacklist(self, email):
		partition = email.partition('@')
		if partition[1]=="":
			return None
		domain = partition[2]
		entry = self.sess().query(BlacklistedEmailDomain).filter(BlacklistedEmailDomain.domain==domain).first()
		if entry:
			return entry
		return None

	def blacklist(self, issuer, domain, reason):
		if not '.' in domain:
			return False, "invalid domain '%s', contains no '.'" % domain
		if 'www' in domain or 'http' in domain or '/' in domain:
			return False, "invalid domain '%s', do not include www or http(s) part, example: hawtmail.com" % domain
		entry = self.sess().query(BlacklistedEmailDomain).filter(BlacklistedEmailDomain.domain==domain).first()
		if entry:
			return False, 'Domain %s is already blacklisted' % domain
		entry = BlacklistedEmailDomain(issuer.user_id, domain, reason)
		self.sess().add(entry)
		self.sess().commit()
		return True, 'Successfully added %s to blacklist' % domain

	def unblacklist(self, issuer, domain):
		entry = self.sess().query(BlacklistedEmailDomain).filter(BlacklistedEmailDomain.domain==domain).first()
		if not entry:
			return False, "Unable to remove %s, entry doesn't exist" % (domain)
		self.sess().delete(entry)
		self.sess().commit()
		return True, "Sucessfully removed %s from blacklist" % domain

	def list_bans(self):
		# return a list of all bans
		banlist = []
		for ban in self.sess().query(Ban):
			username = None
			issuer = None
			if ban.user_id:
				entry = self.sess().query(User).filter(User.id==ban.user_id).first()
				if entry: username = entry.username
			if ban.issuer_user_id:
				issuer =  self.sess().query(User).filter(User.id==ban.issuer_user_id).first()
				if issuer: issuer_username = issuer.username
			banlist.append({
				'username': username or "",
				'id': ban.user_id,
				'ip': ban.ip or "",
				'email': ban.email or "",
				'end_date': ban.end_date.strftime("%Y-%m-%d %H:%M"),
				'reason': ban.reason,
				'issuer': issuer_username
			})
		return banlist

	def list_blacklist(self):
		# return a list of all blacklisted email domains
		blacklist = []
		for item in self.sess().query(BlacklistedEmailDomain):
			issuer =  self.sess().query(User).filter(User.id==item.issuer_user_id).first()
			if issuer: issuer_username = issuer.username
			blacklist.append({
				'domain': item.domain,
				'start_time': item.start_time.strftime("%Y-%m-%d %H:%M"),
				'reason': item.reason or "",
				'issuer': issuer_username
			})
		return blacklist

	def clean(self):
		# remove all expired bans
		now = datetime.now()
		response = self.sess().query(Ban).filter(Ban.end_date < now)
		logging.info("deleting %i expired bans", response.count())
		response.delete(synchronize_session=False)
		self.sess().commit()

class VerificationsHandler:
	def __init__(self, root):
		self._root = root
		
		self.require_verification = False
		try:
			with open('server_email_account.txt') as f:
				lines = f.readlines()
			lines = [l.strip() for l in lines]
			self.mail_user = lines[0]
			self.require_verification = True
			logging.info('Email verification is enabled, server email account is %s' % self.mail_user)
		except Exception as e:
			logging.info('Could not load server_email_account.txt, email verification is disabled: %s' %(e))

	def sess(self):
		return self._root.session_manager.sess()

	def active(self):
		return self.require_verification

	def valid_email_addr(self, email):
		assert(type(email) == str)
		if (not email or email==""):
			return False, "An email address is required."
		if ' ' in email:
			return False, "Invalid email address (check for whitespace)."
		if not re.match(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,6}", email):
			return False, "Invalid email address."
		return True, ""

	def check_and_send(self, user_id, email, digits, reason, use_delay, ip_address):
		# check that we don't already have an active verification, send a new one if not
		if not self.active():
			return True, ''
		good, validity_reason = self.valid_email_addr(email)
		if not good:
			return False, validity_reason
		dbblacklist = self._root.bandb.check_blacklist(email)
		if dbblacklist:
			return False, dbblacklist.domain + " is blacklisted: " + dbblacklist.reason
		# no need to check if ip is banned, that is done by login!

		email_entry = self.sess().query(Verification).filter(Verification.email == email).first()
		if email_entry:
			if datetime.now() <= email_entry.expiry:
				return False, 'a verification attempt is already active for ' + email + ', use that or wait for it to expire (up to 24h)'
		if email_entry: #expired
			self.remove(email_entry.user_id)

		entry = self.sess().query(Verification).filter(Verification.user_id == user_id).first()
		if entry:
			if entry.email != email:
				return False, 'a verification code is active for ' + entry.email + ', use that or wait for it to expire (up to 24h)'
			if datetime.now() < entry.expiry:
				return False, 'already sent a verification code, please check your spam filter!'
		if entry: #expired
			self.remove(user_id)
		entry = self.create(user_id, email, digits, use_delay, reason)
		self.send(entry, ip_address)
		return True, ''

	def create(self, user_id, email, digits, use_delay, reason):
		entry = Verification(user_id, email, digits, use_delay, reason)
		self.sess().add(entry)
		self.sess().commit()
		return entry

	def resend(self, user_id, email, ip_address):
		entry = self.sess().query(Verification).filter(Verification.user_id == user_id).first()
		if not entry:
			return False, 'you do not have an active verification code'
		if entry.expiry <= datetime.now():
			return False, 'your verification code has expired, please request a new one'
		if email!=entry.email:
			return False, 'your verification code for ' + entry.email + ' cannot be re-sent to a different email address, use it or wait for it to expire (up to 24h)'
		if entry.resends>=3:
			return False, 'too many resends, please try again later'
		if entry.resends==0:
			entry.reason += " (resend requested)"
		entry.resends += 1
		self.sess().commit()
		self.send(entry, ip_address)
		return True, ''

	def send(self, entry, ip_address):
		if not self.active(): #safety
			return
		try:
			thread.start_new_thread(self._send, (entry.email, entry.code, entry.reason, entry.use_delay, entry.expiry, ip_address))
		except:
			logging.error('Failed to launch VerificationHandler._send: %s, %s, %s' % (entry, reason, wait_duration))

	def _send(self, email, code, reason, use_delay, expiry, ip_address):
		if use_delay:
			time.sleep(20)
		sent_from = self.mail_user
		to = email
		subject = 'SpringRTS verification code'
		body = """
You are recieving this email because you recently """ + reason + """.
Your email verification code is """ + str(code) + """
<br><br>
This verification code will expire on """ + expiry.strftime("%Y-%m-%d") + """ at """ + expiry.strftime("%H:%M") + """ CET."""
		self._send_email(sent_from, to, subject, body)

	def _send_email(self, sent_from, to, subject, body):
		if not self.active(): #safety
			return
		body += '<br><br>If you received this message in error, please contact us at www.springrts.com. Direct replies to this message will be automatically deleted.'
		message = MIMEText(body, 'html')
		message['Subject'] = subject 
		message['From'] = "SpringRTS <" + sent_from + ">"
		message['To'] = "," + to
		try:
			server = smtplib.SMTP()
			server.connect()
			server.sendmail(sent_from, to, message.as_string())
			server.close()
			logging.info('Sent verification code to %s' % (to))
		except Exception as e:
			logging.error('Failed to send email from %s to %s' % (sent_from, to))
			logging.error(str(e))

	def verify (self, user_id, email, code):
		if not self.active():
			return True, ''
		if code=="":
			return False, 'a verification code is required'
		entry = self.sess().query(Verification).filter(Verification.user_id == user_id).first() # there should be (at most) one code per user
		if not entry:
			logging.error('Unexpected verification attempt: %s, %s' % (user_id, code))
			return False, 'unexpected verification attempt, please request a verification code'
		if entry.expiry <= datetime.now():
			return False, 'your verification code for ' + entry.email + ' has expired, please request a new one'
		if entry.attempts>=3:
			return False, 'too many attempts, please try again later'
		if entry.email!=email:
			return False, 'failed to match email addresses'
		try:
			if entry.code==int(code):
				self.remove(user_id)
				return True, ''
			else:
				entry.attempts += 1
				self.sess().commit()
				return False, 'incorrect verification code, %i/3 attempts remaining' % (3-entry.attempts)
		except Exception as e:
			entry.attempts += 1
			self.sess().commit()
			return False, 'incorrect verification code, ' + str(e) + ', %i/3 attempts remaining' % (3-entry.attempts)

	def remove(self, user_id):
		# remove all entries for user
		self.sess().query(Verification).filter(Verification.user_id == user_id).delete(synchronize_session=False)
		self.sess().commit()

	def clean(self):
		# remove all expired entries
		now = datetime.now()
		response = self.sess().query(Verification).filter(Verification.expiry < now)
		logging.info("deleting %i expired verifications", response.count())
		response.delete(synchronize_session=False)
		self.sess().commit()

	def reset_password(self, user_id):
		# reset pw, email to user
		char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!£$%^&*?"
		new_password_raw = ""
		for i in range(0,10):
			new_password_raw += random.choice(char_set)
		hash = hashlib.md5()
		hash.update(str.encode(new_password_raw))
		new_password = base64.b64encode(hash.digest()).decode()
		assert(self._root.protocol._validPasswordSyntax(new_password))

		dbuser = self.sess().query(User).filter(User.id == user_id).first()
		dbuser.password = new_password
		self.sess().commit()

		try:
			thread.start_new_thread(self._send_reset_password_email, (dbuser.email, dbuser.username, new_password_raw,))
		except:
			logging.error('Failed to launch UserHandler._send_recover_account_email: %s' % (dbuser))

	def _send_reset_password_email(self, email, username, password):
		if not self.active():
			return
		sent_from = self.mail_user
		to = email
		subject = 'SpringRTS account recovery'
		body = """
You are recieving this email because you recently requested to recover the account <""" + username + """> at the SpringRTS lobby server.
Your new password is """ + password
		self._send_email(sent_from, to, subject, body)


class ChannelsHandler:
	def __init__(self, root):
		self._root = root

	def sess(self):
		return self._root.session_manager.sess()

	def channel_from_name(self, name):
		entry = self.sess().query(Channel).filter(Channel.name == name).first()
		return entry

	def channel_from_id(self, channel_id):
		entry = self.sess().query(Channel).filter(Channel.id == channel_id).first()
		return entry

	def all_channels(self):
		response = self.sess().query(Channel)
		channels = {}
		for chan in response:
			channels[chan.name] = {
					'id': chan.id,
					'owner_user_id':chan.owner_user_id,
					'key':chan.key,
					'topic':chan.topic or '',
					'topic_user_id':chan.topic_user_id,
					'antispam':chan.antispam,
					'operator':[],
					'chanserv': True,
					'store_history': chan.store_history,
				}
		return channels

	def all_operators(self):
		response = self.sess().query(ChannelOp)
		operators = []
		for op in response:
			operators.append({
					'channel_id': op.channel_id,
					'user_id': op.user_id,
				})
		return operators

	def all_bans(self):
		response = self.sess().query(ChannelBan)
		bans = []
		for ban in response:
			bans.append({
					'channel_id': ban.channel_id,
					'issuer_user_id': ban.issuer_user_id,
					'user_id': ban.user_id,
					'ip_address': ban.ip_address,
					'expires': ban.expires,
					'reason': ban.reason,
				})
		return bans

	def all_bridged_bans(self):
		response = self.sess().query(ChannelBridgedBan)
		bans = []
		for ban in response:
			bans.append({
					'channel_id': ban.channel_id,
					'bridged_id': ban.bridged_id,
					'issuer_user_id': ban.issuer_user_id,
					'expires': ban.expires,
					'reason': ban.reason,
				})
		return bans

	def all_mutes(self):
		response = self.sess().query(ChannelMute)
		mutes = []
		for mute in response:
			mutes.append({
					'channel_id': mute.channel_id,
					'issuer_user_id': mute.issuer_user_id,
					'user_id': mute.user_id,
					'expires': mute.expires,
					'reason': mute.reason,
				})
		return mutes

	def all_forwards(self):
		response = self.sess().query(ChannelForward)
		forwards = []
		for forward in response:
			forwards.append({
			'channel_from_id': forward.channel_from_id,
			'channel_to_id': forward.channel_to_id,
			})
		return forwards

	def setTopic(self, channel, topic, target):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		if entry:
			entry.topic = topic
			entry.topic_user_id = target.user_id
			self.sess().commit()

	def setKey(self, channel, key):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		if entry:
			entry.key = key
			self.sess().commit()

	def setFounder(self, channel, target):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		if entry:
			entry.owner_user_id = target.user_id
			self.sess().commit()

	def setAntispam(self, channel, antispam):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		if entry:
			entry.antispam = antispam
			self.sess().commit()

	def opUser(self, channel, target):
		entry = ChannelOp(channel.id, target.user_id)
		self.sess().add(entry)
		self.sess().commit()

	def deopUser(self, channel, target):
		entry = self.sess().query(ChannelOp).filter(ChannelOp.user_id == target.user_id).filter(ChannelOp.channel_id == channel.id).first()
		if entry:
			self.sess().delete(entry)
			self.sess().commit()

	def banBridgedUser(self, channel, issuer, target, expires, reason):
		entry = ChannelBridgedBan(channel.id, issuer.user_id, target.bridged_id, expires, reason)
		self.sess().add(entry)
		self.sess().commit()

	def unbanBridgedUser(self, channel, target):
		response = self.sess().query(ChannelBridgedBan).filter(ChannelBridgedBan.bridged_id == target.bridged_id).filter(ChannelBridgedBan.channel_id == channel.id)
		response.delete()
		self.sess().commit()

	def banUser(self, channel, issuer, target, expires, reason):
		entry = ChannelBan(channel.id, issuer.user_id, target.user_id, target.last_ip, expires, reason)
		self.sess().add(entry)
		self.sess().commit()

	def unbanUser(self, channel, target):
		response = self.sess().query(ChannelBan).filter(ChannelBan.user_id == target.user_id).filter(ChannelBan.channel_id == channel.id)
		response.delete()
		self.sess().commit()

	def muteUser(self, channel, issuer, target, expires, reason):
		entry = ChannelMute(channel.id, issuer.user_id, target.user_id, expires, reason)
		self.sess().add(entry)
		self.sess().commit()

	def unmuteUser(self, channel, target):
		response = self.sess().query(ChannelMute).filter(ChannelMute.user_id == target.user_id).filter(ChannelMute.channel_id == channel.id)
		response.delete()
		self.sess().commit()

	def setHistory(self, chan, enable):
		entry = self.sess().query(Channel).filter(Channel.name == chan.name).first()
		if entry:
			entry.store_history = enable
			self.sess().commit()

	def addForward(self, channel_from, channel_to):
		entry = ChannelForward(channel_from.id, channel_to.id)
		self.sess().add(entry)
		self.sess().commit()

	def removeForward(self, channel_from, channel_to):
		entry = self.sess().query(ChannelForward).filter(ChannelForward.channel_from_id == channel_from.id).filter(ChannelForward.channel_to_id == channel_to.id)
		if entry:
			self.sess().delete(entry)
			self.sess().commit()

	def register(self, channel, target):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		if not entry:
			entry = Channel(channel.name)
		if channel.topic:
			entry.topic = channel.topic
			entry.topic_user_id = target.user_id
		entry.owner_user_id = target.user_id
		self.sess().add(entry)
		self.sess().commit()
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		channel.id = entry.id

	def unRegister(self, channel):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).delete()
		self.sess().commit()

	def registered(self, channel):
		entry = self.sess().query(Channel).filter(Channel.name == channel.name).first()
		return bool(entry)
		
	def clean(self):
		#delete all expired channel bans/mutes:
		now = datetime.now()

		response = self.sess().query(ChannelMute).filter(ChannelMute.expires < now)
		logging.info("deleting %i expired channel mutes", response.count())
		response.delete(synchronize_session=False)

		response = self.sess().query(ChannelBan).filter(ChannelBan.expires < now)
		logging.info("deleting %i expired channel bans", response.count())
		response.delete(synchronize_session=False)

		response = self.sess().query(ChannelBridgedBan).filter(ChannelBridgedBan.expires < now)
		logging.info("deleting %i expired channel bridged bans", response.count())
		response.delete(synchronize_session=False)

		self.sess().commit()

if __name__ == '__main__':
	class root:
		censor = False

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
	root.session_manager = session_manager(root, engine)
	
	userdb = UsersHandler(root)
	channeldb = ChannelsHandler(root)
	verificationdb = VerificationsHandler(root)
	bandb = BansHandler(root)
	root.userdb = userdb
	root.channeldb = channeldb
	root.verificationdb = verificationdb
	root.bandb = bandb

	# test save/load user
	username = u"test"
	userdb.register_user(username, u"pass", "192.168.1.1", "blackhole@blackhole.io")
	client = userdb.clientFromUsername(username)
	assert(isinstance(client.id, int))

	# test verification
	entry = verificationdb.create(client.id, client.email, 4, False, "test")
	verificationdb._send_email("test@test.test", "blackhole@blackhole.io", "test", "test") #use main thread, or Python will exit without waiting for the test!
	verificationdb.verify(client.id, client.email, entry.code)
	verificationdb.clean()

	# test ban/unban
	client.user_id = client.id # ban issuer is an *online* client; impersonate one
	userdb.register_user("delinquent", u"pass", "192.168.1.2", "blackhole@blackhole.io")
	client2 = userdb.clientFromUsername("delinquent")
	bandb.ban(client, 1, "test", "delinquent")
	ban = bandb.check_ban(client2.id, None, None)
	assert(ban)
	bandb.unban(client, "delinquent")
	ban = bandb.check_ban(client2.id, None, None)
	assert(not ban)

	# test save/load channel
	channelname = u"testchannel"
	channel = Channel(channelname)
	client.user_id = client.id # only online clients can register channels, so pretend we are one of those
	channeldb.register(channel, client)
	assert(channel.id > 0)

	# test setHistory
	assert(channel.store_history == False)
	channel.store_history = True
	channeldb.setHistory(channel, channel.store_history)
	channel = channeldb.channel_from_name(channelname)
	assert(channel.store_history == True)

	# test channel message history
	now = datetime.now()
	msg = u'test message %d äöüÄÖÜß ?(?_°)?'
	lastid = -1
	for i in range(0, 20):
		if i == 0:
			lastid = userdb.add_channel_message(channel.id, client.id, msg % i, now + timedelta(0, i))
		else:
			userdb.add_channel_message(channel.id, client.id, msg % i, now + timedelta(0, i))

	assert(lastid > -1)

	for i in range(0,21):
		msgs = userdb.get_channel_messages(channel.id, client.id, lastid + i -1)
		assert(len(msgs) == 20 - i)
		if (len(msgs) > 0):
			assert(msgs[0][0] == now + timedelta(0, i))
			assert(msgs[0][1] == client.username)
			assert(msgs[0][2] == msg % i)
			assert(type(msgs[0][2]) == str)

	userdb.add_channel_message(channel.id, None, "test")
	userdb.add_channel_message(channel.id, 99, "test")

	userdb.clean()
	verificationdb.clean()
	bandb.clean()

	print("Tests went ok")


