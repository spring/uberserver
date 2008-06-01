import time

from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, ForeignKey, Boolean
from sqlalchemy.orm import mapper, sessionmaker, relation

#for user in session.query(User).filter(User.name=='ed'):
#	print user

#print session.query(User).\
#	join('addresses', aliased=True).filter(Address.ip_address=='216.7.57.1').all()

#session.query(Address).filter_by(user=user).all()

#engine = create_engine('sqlite:///:memory:')#, echo=True)
#engine = create_engine('sqlite:///database.txt')

#### IMPLEMENT THIS ####
#import sqlalchemy.pool as pool
#import sqlite

#def getconn():
#    return sqlite.connect(filename='myfile.db')

## SQLite connections require the SingletonThreadPool    
#p = pool.SingletonThreadPool(getconn)
#### END ####

engine = create_engine('mysql://uberserver:A2Pb2p3M547EuE47@localhost/uberserver')
metadata = MetaData()

class User(object):
	def __init__(self, name, password, last_ip):
		self.name = name
		self.password = password
		self.last_login = int(time.time())
		self.banned = 0
		self.last_ip = last_ip
		self.ingame_time = 0
		self.bot = 0
		self.access = 'user' # moderator, admin

	def __repr__(self):
		return "<User('%s', '%s')>" % (self.name, self.password)

class Address(object):
	def __init__(self, ip_address):
		self.ip_address = ip_address

	def __repr__(self):
		return "<Address('%s')>" % self.ip_address

class Channel(object):
	def __init__(self, name, owner='', topic='', topic_time=0, topic_owner='', antispam='', admins='', bans='', allow='', mutelist='', autokick='ban', censor=False, antishock=False):
		self.name = name
		self.password = password
		self.owner = owner
		self.topic = topic
		self.topic_time = topic_time
		self.topic_owner = topic_owner
		self.antispam = antispam
		self.admins = admins
		self.bans = bans
		self.allow = allow
		self.mutelist = mutelist
		self.autokick = autokick
		self.censor = censor
		self.antishock = antishock

	def __repr__(self):
		return "<Channel('%s')>" % self.name

users_table = Table('users', metadata,
        Column('id', Integer, primary_key=True),
        Column('name', String(40)),
        Column('password', String(32)),
        Column('last_login', Integer), # use seconds since unix epoch
        Column('banned', Integer), # use seconds since unix epoch
        Column('last_ip', String(15)),
        Column('ingame', Integer),
        Column('access', String(32)),
        Column('bot', Integer)
)
addresses_table = Table('addresses', metadata, 
        Column('id', Integer, primary_key=True),
        Column('ip_address', String(100), nullable=False),
        Column('banned', Integer), # seconds since unix epoch
        Column('user_id', Integer, ForeignKey('users.id')))



{'users':[], 'blindusers':[], 'admins':[], 'ban':{}, 'allow':[], 'autokick':'ban', 'owner':'', 'mutelist':{}, 'antispam':{'enabled':True, 'quiet':False, 'timeout':3, 'bonus':2, 'unique':4, 'bonuslength':100, 'duration':900}, 'censor':False, 'antishock':False, 'topic':None, 'key':None}

channels_table = Table('channels', metadata,
        Column('id', Integer, primary_key=True),
        Column('name', String(40)),
        Column('password', String(32)),
        Column('owner', String(40)),
        Column('topic', Integer),
        Column('topic_time', Integer),
        Column('topic_owner', String(40)),
	Column('antispam', String), # pickles :)
	Column('admins', String),   # pickle these
	Column('bans', String),     # if not specifying length doesn't work, set to like 10k for admin/ban/allow and actually figure out the max logical length for antispam
	Column('allow', String)     #
	Column('mutelist', String),
	Column('autokick', String(10)),
	Column('censor', Boolean),
	Column('antishock', Boolean),
)

mapper(User, users_table, properties={    
        'addresses':relation(Address, backref='user', cascade="all, delete, delete-orphan")
        })
mapper(Address, addresses_table)
metadata.create_all(engine)

class UsersHandler:
	def __init__(self):
                Session = sessionmaker(bind=engine, autoflush=True, transactional=True)
                self.session = Session()

	def login_user(self, user, password, ip):
		good = True
		now = int(time.time())
		entry = self.session.query(User).filter(User.name==user).first() # should only ever be one user with each name so we can just grab the first one :)
		reason = entry
		if not entry:
			return False, 'No user named %s'%user
		if not password == entry.password:
			good = False
			reason = 'Invalid password'
		if entry.banned > 0:
			if entry.banned > now:
				good = False
				timeleft = entry.banned - now
				daysleft = '%.2f'%(float(seconds) / 60 / 60 / 24)
				if daysleft >= 1:
					reason = 'You are banned: (%s) days remaining.' % daysleft
				else:
					reason = 'You are banned: (%s) hours remaining.' % (float(seconds) / 60 / 60)
		exists = self.session.query(Address).filter(Address.user_id==entry.id).first()
		if not exists:
        		entry.addresses.append(Address(ip_address=ip))
		entry.last_login = now
		entry.last_ip = ip
		self.session.commit()
		return good, reason

	def register_user(self, user, password, ip): # need to add better ban checks so it can check if an ip address is banned when registering an account :)
		results = self.session.query(User).filter(User.name==user).first()
		if results:
			return False, 'Username already exists.'
		entry = User(user, password, ip)
        	entry.addresses.append(Address(ip_address=ip))
		self.session.save(entry)
		self.session.commit()
		return True, 'Account registered successfully.'

	def rename_user(self, user, newname):
		entry = self.session.query(User).filter(User.name==user).first()
		entry.name = newname
		self.session.save(entry)
		self.session.commit()

	def remove_user(self, user):
		entry = self.session.query(User).filter(User.name==user).first()
		if not entry:
			return False, 'User not found.'
		self.session.delete(entry)
		self.session.commit()
		return True, 'Success.'

	def load_channels(self):
		return

	def save_channels(self, channels): # pickle lists, maybe gz them
		return
