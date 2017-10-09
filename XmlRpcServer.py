#!/usr/bin/python3
# coding=utf-8
# This file is part of the uberserver (GPL v2 or later), see LICENSE
# xmlrpc class for auth of replays.springrts.com
#
# TODO:
#  - move SQLAlchemy calls to SQLUsers.py

from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from base64 import b64encode
import os.path
import logging
import socket
import traceback
import dbconfig
from logging.handlers import TimedRotatingFileHandler

from SQLUsers import User, Rename, Login, BanUser
import SQLUsers
import sqlalchemy
import datetime

from Crypto.Hash import MD5
LEGACY_HASH_FUNC = MD5.new

# logging
xmlrpc_logfile = os.path.join(os.path.dirname(__file__), "xmlrpc.log")
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
fh = TimedRotatingFileHandler(xmlrpc_logfile, when="midnight", backupCount=6)
formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-5s %(module)s.%(funcName)s:%(lineno)d  %(message)s',
				datefmt='%Y-%m-%d %H:%M:%S')
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)

sqlurl = dbconfig.sqlurl
xmlhost = "localhost"
xmlport = 8300

engine = sqlalchemy.create_engine(sqlurl, echo=False)
userdb = SQLUsers.UsersHandler(None, engine)

class RequestHandler(SimpleXMLRPCRequestHandler):
	def log_message(self, format, *args):
		logger.info(format % args)

class XmlRpcServer(SimpleXMLRPCServer):
	"""
		XMLRPC service, exported functions are in class _RpcFuncs
	"""
	def __init__(self, host, port):
		super(XmlRpcServer, self).__init__((host, port), requestHandler=RequestHandler)
		self.register_introspection_functions()
		self.register_instance(_RpcFuncs())
		logger.info('Listening for XMLRPC clients on %s:%d', host, port)
		self.serve_forever()



def validateLogin(username, password):

	session = userdb.sessionmaker()

	db_user = session.query(User.id, User.username, User.ingame_time, User.email, User.password, User.access).filter(User.username == username).first()
	if not db_user:
		session.close()
		logger.warning("User not found: %s" %(username))
		return {"status": 1}

	if not db_user.password == b64encode(LEGACY_HASH_FUNC(password.encode()).digest()).decode():
		session.close()
		logger.error("Invalid password: %s" %(username))
		return {"status": 1}

	if not db_user.access in ['mod', 'user', 'admin']:
		session.close()
		logger.error("User has no access: <%s> %s" %(username, db_user.access))
		return {"status": 1}

	banned = session.query(BanUser.reason).filter(BanUser.user_id == db_user.id, datetime.datetime.now() <= BanUser.end_time).first()
	if banned:
		session.close()
		logger.warning("User is banned: %s" %(username, banned.reason))
		return {"status": 1}

	renames = session.query(Rename.original).distinct(Rename.original).filter(Rename.user_id == db_user.id).all()
	renames = [ r[0] for r in renames]

	country = session.query(Login.country).filter(Login.user_dbid == db_user.id).filter(sqlalchemy.and_(Login.country != '??', Login.country != None, Login.country != '')).first()
	result = {"status": 0, "accountid": int(db_user.id), "username": str(db_user.username),
			"ingame_time": int(db_user.ingame_time), "email": str(db_user.email),
			"aliases": renames,
			"country": country[0] if country else ''
		 }
	session.close()
	logger.info("validation success: %s" % (username))
	return result

class _RpcFuncs(object):
	"""
		All methods of this class will be exposed via XMLRPC.
	"""

	def get_account_info(self, username, password):
		try:
			return validateLogin(username, password)
		except Exception as e:
			logger.error('Exception: %s: %s' %(str(e), str(traceback.format_exc())))
			return {"status": 1}
try:
	xmlrpcserver = XmlRpcServer(xmlhost, xmlport)
except socket.error:
	logger.error('Error: Could not start XmlRpcServer.')


