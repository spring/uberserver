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
engine = create_engine('mysql://uberserver:A2Pb2p3M547EuE47@localhost/uberserver')
metadata = MetaData()

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

# channel SQL data will be implemented later
#channels_table = Table('channels', metadata,
#        Column('id', Integer, primary_key=True),
#        Column('name', String(40)),
#        Column('password', String(32)),
#        Column('owner', String(40)),
#        Column('topic', Integer),
#        Column('topic_time', String(15)),
#        Column('topic_owner', Integer),
#        Column('type', String(32))
#)

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

	def remove_user(self, user):
		entry = self.session.query(User).filter(User.name==user).first()
		if not entry:
			return False, 'User not found.'
		self.session.delete(entry)
		self.session.commit()
		return True, 'Success.'
