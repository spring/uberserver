# WARNING: this module is only for *reading* from the database. you can't expect the types to fully work, or work at all when writing.
# furthermore, this database layer will not generate correct tables for use with tasserver.

import time

from sqlalchemy import create_engine, Table, Column, Integer, MetaData, Boolean, Text, VARCHAR, TIMESTAMP
from sqlalchemy.exceptions import OperationalError
from sqlalchemy.orm import mapper, sessionmaker

## ip2long helper
import socket, struct

def ip2long(ip):
	packed = socket.inet_aton(ip)
	return struct.unpack("!L", packed)[0]
## end helper

metadata = MetaData()

class Ban(object):
	def __repr__(self):
		return "<Ban('%s', '%s')>" % (self.Username, self.ExpirationDate)

bans_table = Table('ban_groups', metadata, # server bans
	Column('ID', Integer, primary_key=True),
	Column('Enabled', Boolean),
	Column('Owner', VARCHAR(30)),
	Column('Date', TIMESTAMP),
	Column('ExpirationDate', TIMESTAMP),
	Column('Username', VARCHAR(30)),
	Column('IP_start', Integer),
	Column('IP_end', Integer),
	Column('userID', Integer),
	Column('PrivateReason', Text),
	Column('PublicReason', Text)
	)

mapper(Ban, bans_table)

class BanHandler:
	def __init__(self, root, dburl):
		self._root = root
		self.dburl = dburl
		self.engine = create_engine(dburl, pool_size=root.max_threads*2, pool_recycle=300)
		self.sessionmaker = sessionmaker(bind=self.engine, autoflush=True, transactional=True)
	
	def check_ban(self, username=None, ip=None, userid=None):
		if not username and not ip and not userid: return
		session = self.sessionmaker()
		
		entry = None
		if username:
			entry = session.query(Ban).filter(Ban.username==username).first()
		if not entry and userid: # ban priority is username > userid > ip # skips these if statements when we find a ban
			entry = session.query(Ban).filter(Ban.userID==userid).first()
		if not entry and ip:
			longip = ip2long(ip)
			entry = session.query(Ban).filter(Ban.IP_start<=longip).filter(Ban.IP_end>=IP_end).first()
		
		if entry:
			return False, entry.PublicReason
		else:
			return True, None