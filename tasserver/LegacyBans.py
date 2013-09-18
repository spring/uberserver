# WARNING: this module is only for *reading* from the database. you can't expect the types to fully work, or work at all when writing.
# furthermore, this database layer will not generate correct tables for use with tasserver.

import datetime, traceback

from sqlalchemy import create_engine, Table, Column, Integer, MetaData, Boolean, Text, VARCHAR, TIMESTAMP
from sqlalchemy.orm import mapper, sessionmaker
from sqlalchemy.sql import or_

## ip2long helper
import socket, struct
import time

def ip2long(ip):
	packed = socket.inet_aton(ip)
	return struct.unpack("!L", packed)[0]

def long2ip(l):
	L = struct.pack('!L', l)
	return socket.inet_ntoa(L)
## end helper

metadata = MetaData()

class Ban(object):
	def __init__(self, owner, duration, reason, username=None, user_id=None, ip=None, ip_end=None):
		self.Owner = owner
		self.Date = time.time()
		self.ExpirationDate = time.time() + duration * 24*60*60

		if username:
			self.Username = username

		if ip:
			ip = ip2long(ip)
			if ip_end:
				ip_end = ip2long(ip_end)
			else:
				ip_end = ip

			self.IP_start = ip
			self.IP_end = ip_end

		if user_id:
			self.userID = int(user_id)

		self.Enabled = 1

	def __repr__(self):
		return "<Ban('%s', '%s')>" % (self.Username, self.ExpirationDate)

bans_table = Table('BanEntries', metadata, # server bans
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
		self.sessionmaker = sessionmaker(bind=self.engine)

	def check_ban(self, username=None, ip=None, userid=None):
		if not username and not ip and not userid: return False, 'no user specified'

		try:
			session = self.sessionmaker()

			query = session.query(Ban).filter(Ban.Enabled==True).filter(or_(Ban.ExpirationDate == None, Ban.ExpirationDate > datetime.datetime.now()))

			entry = None
			if username:
				entry = query.filter(Ban.Username==username.lower()).first()
			if not entry and userid: # ban priority is username > userid > ip # skips these if statements when we find a ban
				entry = query.filter(Ban.userID==userid).first()
			if not entry and ip:
				longip = ip2long(ip)
				entry = query.filter(Ban.IP_start<=longip).filter(Ban.IP_end>=longip).first()

			if entry:
				return False, entry.PublicReason
			else:
				return True, None
		except Exception: # probably a mysql operational error
			self._root.error(traceback.format_exc())
			return True, None

	def ban_user(self, owner, username, user_id, duration, reason):
		session = self.sessionmaker()
		ban = Ban(owner, duration, reason, username=username.lower(), user_id=user_id)
		session.save(ban)
		session.commit()
		session.close()
		return 'Successfully banned %s for %s days.' % (username, duration)

	def unban_user(self, username, user_id):
		session = self.sessionmaker()
		results = session.query(Ban).filter(Ban.Enabled==True).filter(or_(Ban.ExpirationDate == None, Ban.ExpirationDate > datetime.datetime.now()))
		results = results.filter(or_(Ban.Username==username.lower(), Ban.userID==user_id))
		if results:
			for result in results:
				session.delete(result.ban)
			session.commit()
			session.close()
			return 'Successfully unbanned %s.' % username
		else:
			session.close()
			return 'No matching bans for %s.' % username

	def ban_ip(self, owner, ip, duration, reason):
		session = self.sessionmaker()
		ban = Ban(owner, duration, reason, ip=ip)
		session.save(ban)
		session.commit()
		session.close()
		return 'Successfully banned %s for %s days.' % (ip, duration)

	def unban_ip(self, ip):
		session = self.sessionmaker()
		results = session.query(Ban).filter(Ban.Enabled==True).filter(or_(Ban.ExpirationDate == None, Ban.ExpirationDate > datetime.datetime.now()))
		results = results.filter(Ban.Username==ip.lower())
		if results:
			for result in results:
				session.delete(result.ban)
			session.commit()
			session.close()
			return 'Successfully unbanned %s.' % ip
		else:
			session.close()
			return 'No matching bans for %s.' % ip

	def banlist(self):
		bans = []

		session = self.sessionmaker()
		results = session.query(Ban).filter(Ban.Enabled==True).filter(or_(Ban.ExpirationDate == None, Ban.ExpirationDate > datetime.datetime.now()))
		for ban in results:
			bans.append('%s, %s, %s, %s, %s' % (ban.Username, ban.IP, ban.userID, ban.ExpirationDate, ban.Owner))

		session.close()
		return bans
