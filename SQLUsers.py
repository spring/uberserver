import time

from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, ForeignKey, Boolean, Text
from sqlalchemy.exceptions import OperationalError
from sqlalchemy.orm import mapper, sessionmaker, relation

#for user in session.query(User).filter(User.name=='ed'):
#	print user

#print session.query(User).\
#	join('addresses', aliased=True).filter(Address.ip_address=='216.7.57.1').all()

#session.query(Address).filter_by(user=user).all()

#engine = create_engine('sqlite:///:memory:')#, echo=True)
#engine = create_engine('sqlite:///database.txt')

#### IMPLEMENT THIS #### ...maybe not...
#import sqlalchemy.pool as pool
#import sqlite

#def getconn():
#    return sqlite.connect(filename='myfile.db')

## SQLite connections require the SingletonThreadPool    
#p = pool.SingletonThreadPool(getconn)
#### END ####

#engine = create_engine('mysql://uberserver:A2Pb2p3M547EuE47@localhost/uberserver')
metadata = MetaData()

class User(object):
	def __init__(self, name, casename, password, last_ip, access='agreement'):
		self.name = name
		self.casename = casename
		self.password = password
		self.last_login = int(time.time())
		self.register_date = int(time.time())
		self.last_ip = last_ip
		self.ingame_time = 0
		self.bot = 0
		self.access = access # user, moderator, admin, bot, agreement
		self.hook_chars = ''

	def __repr__(self):
		return "<User('%s', '%s')>" % (self.name, self.password)

class Login(object):
	def __init__(self, now, ip_address, lobby_id, user_id, cpu, local_ip, country):
		self.time = now
		self.ip_address = ip_address
		self.lobby_id = lobby_id
		self.user_id = user_id
		self.cpu = cpu
		self.local_ip = local_ip
		self.country = country
		self.end = 0

	def __repr__(self):
		return "<Login('%s', '%s')>" % (self.ip_address, self.time)

class Rename(object):
	def __init__(self, original, new):
		self.original = original
		self.new = new
		self.time = int(time.time())
		
	def __repr__(self):
		return "<Rename('%s')>" % self.ip_address

class Channel(object):
	def __init__(self, name, password='', chanserv=False, owner='', topic='', topic_time=0, topic_owner='', antispam='', admins='', autokick='ban', censor=False, antishock=False):
		self.name = name
		self.password = password
		self.chanserv = chanserv
		self.owner = owner
		self.topic = topic
		self.topic_time = topic_time
		self.topic_owner = topic_owner
		self.antispam = antispam
		self.admins = admins
		self.allow = allow
		self.autokick = autokick
		self.censor = censor
		self.antishock = antishock

	def __repr__(self):
		return "<Channel('%s')>" % self.name

class ChanUser(object):
	def __init__(self, name, channel, admin=False, banned='', allowed=False, mute=0):
		self.name = name
		self.channel = channel
		self.admin = admin
		self.banned = banned
		self.allowed = allowed
		self.mute = mute

	def __repr__(self):
		return "<ChanUser('%s')>" % self.name

class Antispam(object):
	def __init__(self, enabled, quiet, duration, timeout, bonus, unique, bonuslength):
		self.enabled = enabled
		self.quiet = quiet
		self.duration = duration
		self.timeout = timeout
		self.bonus = bonus
		self.unique = unique
		self.bonuslength = bonuslength

	def __repr__(self):
		return "<Antispam('%s')>" % self.channel

class Ban(object):
	def __init__(self, reason, end_time):
		self.reason = reason
		self.end_time = end_time
	
	def __repr__(self):
		return "<Ban('%s')>" % self.end_time

class AggregateBan(object):
	def __init__(self, ban_type, data):
		self.ban_type = ban_type
		self.data = data
	
	def __repr__(self):
		return "<AggregateBan('%s')('%s')>" % (self.ban_type, self.data)

users_table = Table('users', metadata,
	Column('id', Integer, primary_key=True),
	Column('name', String(40)),
	Column('casename', String(40)),
	Column('password', String(32)),
	Column('register_date', Integer),
	Column('last_login', Integer), # use seconds since unix epoch # should replace these with last_session or just remove them
	Column('last_ip', String(15)), # would need update for ipv6   # 
	Column('last_id', String(128)),
	Column('ingame_time', Integer),
	Column('access', String(32)),
	Column('bot', Integer),
	Column('hook_chars', String(4)),
	)

logins_table = Table('logins', metadata, 
	Column('id', Integer, primary_key=True),
	Column('ip_address', String(15), nullable=False),
	Column('time', Integer),
	Column('lobby_id', String(128)),
	Column('cpu', Integer),
	Column('local_ip', String(15)),
	Column('country', String(4)),
	Column('end', Integer),
	Column('user_id', Integer),
	Column('user_dbid', Integer, ForeignKey('users.id')),
	)

renames_table = Table('renames', metadata,
	Column('id', Integer, primary_key=True),
	Column('user_id', Integer, ForeignKey('users.id')),
	Column('original', String(40)),
	Column('new', String(40)),
	Column('time', Integer),
	)

channels_table = Table('channels', metadata,
	Column('id', Integer, primary_key=True),
	Column('name', String(40)),
	Column('password', String(32)),
	Column('owner', String(40)),
	Column('topic', Integer),
	Column('topic_time', Integer),
	Column('topic_owner', String(40)),
	Column('antispam_id', Integer, ForeignKey('antispam.id')),
	Column('autokick', String(5)),
	Column('censor', Boolean),
	Column('antishock', Boolean),
	)

chanuser_table = Table('chanuser', metadata,
	Column('id', Integer, primary_key=True),
	Column('name', String(40)),
	Column('channel', String(40)),
	Column('admin', Boolean),
	Column('banned', Boolean),
	Column('allowed', Boolean),
	Column('mute', Integer),
	)

antispam_table = Table('antispam', metadata,
	Column('id', Integer, primary_key=True),
	Column('enabled', Boolean),
	Column('quiet', Boolean),
	Column('duration', Integer),
	Column('timeout', Integer),
	Column('bonus', Integer),
	Column('unique', Integer),
	Column('bonuslength', Integer),
	)

bans_table = Table('ban_groups', metadata, # server bans
	Column('id', Integer, primary_key=True),
	Column('reason', Text),
	Column('end_time', Integer), # seconds since unix epoch
	)

aggregatebans_table = Table('ban_items', metadata, # server bans
	Column('id', Integer, primary_key=True),
	Column('type', String(10)), # what exactly is banned (username, ip, subnet, hostname, (ip) range, userid, )
	Column('data', String(60)), # regex would be cool
	Column('ban_id', Integer, ForeignKey('ban_groups.id')),
	)

mapper(User, users_table, properties={
	'logins':relation(Login, backref='user', cascade="all, delete, delete-orphan"),
	'renames':relation(Rename, backref='user', cascade="all, delete, delete-orphan"),
	})
mapper(Login, logins_table)
mapper(Rename, renames_table)
mapper(Channel, channels_table, properties={
	'antispam':relation(Antispam, backref='channel', cascade="all, delete, delete-orphan"),
	})
mapper(ChanUser, chanuser_table)
mapper(Antispam, antispam_table)
mapper(Ban, bans_table, properties={
	'entries':relation(AggregateBan, backref='ban', cascade="all, delete, delete-orphan"),
	})
mapper(AggregateBan, aggregatebans_table)

#metadata.create_all(engine)

class UsersHandler:
	def __init__(self, root, engine):
		self._root = root
		metadata.create_all(engine)
		Session = sessionmaker(bind=engine, autoflush=True, transactional=False)
		self.session = Session()
	
	def check_ban(self, user=None, ip=None, userid=None):
		return
		results = self.session.query(AggregateBan)
		subnetbans = results.filter(AggregateBan.type=='subnet')
		userban = results.filter(AggregateBan.type=='user').filter(AggregateBan.data==user)
		ipban = results.filter(AggregateBan.type=='ip').filter(AggregateBan.data==ip)
		useridban = results.filter(AggregateBan.type=='userid').filter(AggregateBan.data==userid)
		
	def login_user(self, user, password, ip, lobby_id, user_id, cpu, local_ip, country):
		name = user.lower()
		lanadmin = self._root.lanadmin
		if user == lanadmin['username'] and password == lanadmin['password']:
			sqluser = User(name, lanadmin['username'], password, ip, 'admin')
			return True, sqluser
		good = True
		now = int(time.time())
		entry = self.session.query(User).filter(User.name==name).first() # should only ever be one user with each name so we can just grab the first one :)
		reason = entry
		if not entry:
			return False, 'No user named %s'%user
		if not password == entry.password:
			good = False
			reason = 'Invalid password'
		#if entry.banned > 0: # update with time remaining from protocol or wherever it is
			#if entry.banned > now:
				#good = False
				#timeleft = entry.banned - now
				#daysleft = '%.2f'%(float(seconds) / 60 / 60 / 24)
				#if daysleft >= 1:
					#reason = 'You are banned: (%s) days remaining.' % daysleft
				#else:
					#reason = 'You are banned: (%s) hours remaining.' % (float(seconds) / 60 / 60)
		entry.logins.append(Login(now, ip, lobby_id, user_id, cpu, local_ip, country))
		entry.last_login = now
		entry.last_ip = ip
		entry.last_id = user_id
		#self.session.commit()
		return good, reason
	
	def end_session(self, username):
		name = username.lower()
		entry = self.session.query(User).filter(User.name==name).first()
		if not entry.logins[-1].end: entry.logins[-1].end = time.time()

	def register_user(self, user, password, ip): # need to add better ban checks so it can check if an ip address is banned when registering an account :)
		if self._root.censor:
			if not self._root.SayHooks._nasty_word_censor(user):
				return False, 'Name failed to pass profanity filter.'
		name = user.lower()
		results = self.session.query(User).filter(User.name==name).first()
		lanadmin = self._root.lanadmin
		if name == lanadmin['username'].lower():
			if password == lanadmin['password']: # if you register a lanadmin account with the right user and pass combo, it makes it into a normal admin account
				if user in self._root.usernames:
					self._root.usernames[user]
				entry = User(name, lanadmin['username'], password, ip, 'admin')
				entry.addresses.append(Address(ip_address=ip))
				self.session.save(entry)
				#self.session.commit()
				return True, 'Account registered successfully.'
			else: return False, 'Username already exists.'
		if results:
			return False, 'Username already exists.'
		entry = User(name, user, password, ip)
		self.session.save(entry)
		#self.session.commit()
		return True, 'Account registered successfully.'
	
	def ban_user(self, username, duration, reason):
		name = username.lower()
		entry = self.session.query(User).filter(User.name==name).first()
		end_time = int(time.time()) + duration
		ban = Ban(reason, end_time)
		self.session.save(ban)
		ban.entries.append(AggregateBan('user', name))
		ban.entries.append(AggregateBan('ip', entry.last_ip))
		ban.entries.append(AggregateBan('userid', entry.last_id))
		return 'Successfully banned %s for %s days.' % (username, duration)
	
	def unban_user(self, username):
		results = self.session.query(AggregateBan).filter(AggregateBan.type=='user').filter(AggregateBan.data==user)
		if results:
			for result in results:
				self.session.delete(result.ban)
			return 'Successfully unbanned %s.' % username
		else:
			return 'No matching bans for %s.' % username
	
	def banlist(self):
		banlist = []
		for ban in self.session.query(Ban):
			current_ban = '%s (%s)' % (ban.end_time, ban.reason)
			for entry in ban.entries:
				current_ban += ' (%s - %s)' % (entry.ban_type, entry.data)
		return banlist

	def rename_user(self, user, newname):
		if self._root.censor:
			if not self._root.SayHooks._nasty_word_censor(user):
				return False, 'Name failed to pass profanity filter.'
		lnewname = newname.lower()
		results = self.session.query(User).filter(User.name==lnewname).first()
		if results:
			return False, 'Username already exists.'
		entry = self.session.query(User).filter(User.name==user.lower()).first()
		if not entry: return False, 'You don\'t seem to exist anymore. Contact an admin or moderator.'
		entry.name = lnewname
		entry.casename = newname
		#self.session.save(entry)
		#self.session.commit()
		# need to iterate through channels and rename junk there...
		# it might actually be a lot easier to use userids in the server...
		return True, 'Account renamed successfully.'
	
	def save_user(self, client):
		name = client.username.lower()
		entry = self.session.query(User).filter(User.name==name).first()
		if entry:
			entry.ingame_time = client.ingame_time
			entry.access = client.access
			entry.bot = client.bot
			entry.hook_chars = client.hook
	
	def confirm_agreement(self, client):
		name = client.username.lower()
		entry = self.session.query(User).filter(User.name==name).first()
		if entry: entry.access = 'user'

	def remove_user(self, user):
		entry = self.session.query(User).filter(User.name==user).first()
		if not entry:
			return False, 'User not found.'
		self.session.delete(entry)
		#self.session.commit()
		return True, 'Success.'
	
	def load_channels(self):
		response = self.session.query(Channel)
		for channel in response:
			channels.append({})
		return channels
	
	def save_channel(self, channel):
		entry = self.session.query(Channel)
		entry.password = channel['password']
		entry.chanserv = channel['chanserv']
		entry.owner = channel['owner']
		topic = channel['topic']
		if topic:
			topic = topic['text']
			topic_time = topic['time']
			topic_owner = topic['owner']
		else:
			topic, topic_time, topic_owner = ('', 0, '')
		entry.topic = topic
		entry.topic_time = topic_time
		entry.topic_owner = topic_owner
		#entry.antispam = channel[]
		entry.autokick = channel['autokick']
		entry.censor = channel['censor']
		entry.antishock = channel['antishock']
		self.session.save(entry)

	def save_channels(self, channels):
		for channel in channels:
			self.save_channel(channel)
		#self.session.commit()
