#
# xmlrpc class for auth of replays.springrts.com
#
# TODO:
#  - remove dependency to Protocol.py
#  - move SQLAlchemy calls to SQLUsers.py

import BaseHTTPServer
from SimpleXMLRPCServer import SimpleXMLRPCServer
from base64 import b64encode
import os.path
import logging
from logging.handlers import TimedRotatingFileHandler

from protocol import Protocol
from CryptoHandler import MD5LEG_HASH_FUNC as LEGACY_HASH_FUNC
from SQLUsers import User

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


def _xmlrpclog(self, format, *args):
	logger.debug("%s - %s" , self.client_address[0], format%args)

# overwrite default logger, because it will otherwise spam main server log
BaseHTTPServer.BaseHTTPRequestHandler.log_message = _xmlrpclog


class XmlRpcServer(object):
	"""
	XMLRPC service, exported functions are in class _RpcFuncs
	"""
	def __init__(self, root, host, port):
		self._root = root
		self.host = host
		self.port = port
		self._server = SimpleXMLRPCServer((self.host, self.port))
		self._server.register_introspection_functions()
		self._server.register_instance(_RpcFuncs(self._root))

	def start(self):
		logger.info('Listening for XMLRPC clients on %s:%d', self.host, self.port)
		self._server.serve_forever()

	def shutdown(self):
		self._server.shutdown()


class _RpcFuncs(object):
	"""
	All methods of this class will be exposed via XMLRPC.
	"""
    def __init__(self, root):
        self._root = root
        self._proto = Protocol.Protocol(self._root)

    def get_account_info(self, username, password):
	password_enc = unicode(b64encode(LEGACY_HASH_FUNC(password).digest()))
	good = self._proto._testlogin(unicode(username), password_enc) # FIXME: don't use Protocol.py
	logger.debug("reply: %s", good)
	if not good:
		return {"status": 1}
	session = self._root.userdb.sessionmaker() # FIXME: move to SQLUsers.py
	db_user = session.query(User).filter(User.username == username).first()
	renames = list()
	for rename in db_user.renames:
		renames.append(rename.original)
	if db_user.renames:
		renames.append(db_user.renames[-1].new)
	renames = set(renames) # HACK to remove duplicates
	result = {"status": 0, "accountid": int(db_user.id), "username": str(db_user.username),
		"ingame_time": int(db_user.ingame_time), "email": str(db_user.email),
		"aliases": list(renames)}
	try:
		result["country"] = db_user.logins[-1].country
	except:
		result["country"] = ""
	return result

