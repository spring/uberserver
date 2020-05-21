#!/usr/bin/env python3
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

from SQLUsers import User, Rename, Login, Ban
import SQLUsers
import sqlalchemy
import datetime

from hashlib import md5

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

class DummyRoot:
	def __init__(self):
		self.engine = sqlalchemy.create_engine(sqlurl, echo=False)
		self.session_manager = SQLUsers.session_manager(self, self.engine)
		self.userdb = SQLUsers.UsersHandler(self)
		self.bandb = SQLUsers.BansHandler(self)

root = DummyRoot()
		
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

def validateLogin(username, raw_password):

	session = root.userdb.sess()
	
	password = b64encode(md5(raw_password.encode()).digest()).decode()
	good, reason = root.userdb.check_login_user(username, password)
	if not good:
		logger.info("validation failure: {}, {}".format(username, reason))
		return {"status": 1}

	banned, reason = root.userdb.check_banned(username, None)
	if banned:
		logger.info("validation failure: {}, {}".format(username, reason))
		return {"status": 1}

	db_user = session.query(User).filter(User.username == username).first()
	renames = session.query(Rename.original).distinct(Rename.original).filter(Rename.user_id == db_user.id).all()
	renames = [r[0] for r in renames]
	country = session.query(Login.country).filter(Login.user_id == db_user.id).filter(sqlalchemy.and_(Login.country != '??', Login.country is not None, Login.country != '')).first()
	result = {"status": 0, "accountid": int(db_user.id), "username": str(db_user.username),
			"ingame_time": int(db_user.ingame_time), "email": str(db_user.email),
			"aliases": renames,
			"country": country[0] if country else ''
		 }
	
	db_user.last_login = datetime.datetime.now()
	logger.info("validation success: {}".format(username))
	return result


def user_id(username):
	session = root.userdb.sess()
	db_user = session.query(User.id).filter(User.username == username).first()
	return db_user.id
	
class _RpcFuncs(object):
	"""
		All methods of this class will be exposed via XMLRPC.
	"""

	def get_account_info(self, username, password):
		ret = {"status": 1}
		try:
			ret = validateLogin(username, password)
			root.session_manager.commit_guard()
		except Exception as e:
			logger.error('Exception: {}: {}'.format(e, traceback.format_exc()))
			root.session_manager.rollback_guard()
		finally:
			root.session_manager.close_guard()
		return ret

	def get_account_id(self, username):
		ret = None
		try:
			ret = user_id(username)
			root.session_manager.commit_guard()				
		except Exception as e:
			logger.error('Exception: {}: {}'.format(e, traceback.format_exc()))
			root.session_manager.rollback_guard()
		finally:
			root.session_manager.close_guard()
		return ret


try:
	xmlrpcserver = XmlRpcServer(xmlhost, xmlport)
except socket.error:
	logger.error('Error: Could not start XmlRpcServer.')


