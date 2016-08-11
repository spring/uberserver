#!/usr/bin/python
# coding=utf-8
# This file is part of the uberserver (GPL v2 or later), see LICENSE
# xmlrpc class for auth of replays.springrts.com
#
# TODO:
#  - move SQLAlchemy calls to SQLUsers.py

import BaseHTTPServer
from SimpleXMLRPCServer import SimpleXMLRPCServer
from base64 import b64encode
import os.path
import logging
import socket
import traceback
from logging.handlers import TimedRotatingFileHandler

from SQLUsers import User, Rename, Login
import SQLUsers
from sqlalchemy import and_
import sqlalchemy

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

sqlurl = 'sqlite:///server.db'
xmlhost = "localhost"
xmlport = 8300

engine = sqlalchemy.create_engine(sqlurl)
userdb = SQLUsers.UsersHandler(None, engine)

def _xmlrpclog(self, format, *args):
	logger.debug("%s - %s" , self.client_address[0], format%args)

# overwrite default logger, because it will otherwise spam main server log
BaseHTTPServer.BaseHTTPRequestHandler.log_message = _xmlrpclog

class XmlRpcServer(object):
	"""
		XMLRPC service, exported functions are in class _RpcFuncs
	"""
	def __init__(self, host, port):
		self._server = SimpleXMLRPCServer((host, port))
		self._server.register_introspection_functions()
		self._server.register_instance(_RpcFuncs())
		logger.info('Listening for XMLRPC clients on %s:%d', host, port)
		self._server.serve_forever()

	def shutdown(self):
		self._server.shutdown()


def validateLogin(username, password):
	password_enc = unicode(b64encode(LEGACY_HASH_FUNC(password).digest()))

	user = userdb.clientFromUsername(username)
	if not user:
		logger.warning("User not found: %s" %(username))
		return {"status": 1}
	good = userdb.legacy_test_user_pwrd(user, password_enc)
	logger.debug("reply: %s", good)
	if not good:
		logger.error("Invalid password: %s" %(username))
		return {"status": 1}
	session = userdb.sessionmaker() # FIXME: move to SQLUsers.py
	db_user = session.query(User.id, User.username, User.ingame_time, User.email).filter(User.username == username).first()
	renames = session.query(Rename.original).distinct(Rename.original).filter(Rename.user_id == db_user.id).all()
	renames = [ r[0] for r in renames]

	country = session.query(Login.country).filter(and_(Login.country != '??', Login.country != None, Login.country != '')).first()
	result = {"status": 0, "accountid": int(db_user.id), "username": str(db_user.username),
			"ingame_time": int(db_user.ingame_time), "email": str(db_user.email),
			"aliases": renames,
			"country": country[0] if country else ''
		 }
	session.close()
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


