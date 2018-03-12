
class Battle():
	def __init__(self, root, id, type, natType, password, port, maxplayers,
						hashcode, rank, maphash, map, title, modname,
						passworded, host, users):
		self._root = root
		self.id = id
		self.type = type
		self.natType = natType
		self.password = password
		self.port = port
		self.maxplayers = maxplayers
		self.spectators = 0
		self.hashcode = hashcode
		self.rank = rank
		self.maphash = maphash
		self.map = map
		self.title = title
		self.modname = modname
		self.passworded = passworded
		self.users = users # list with all session_ids of joined users
		self.host = host # client.session_id
		self.startrects = {}
		self.disabled_units = []

		self.pending_users = set()

		self.engine = 'spring'
		self.version = root.latestspringversion

		self.bots = {}
		self.script_tags = {}
		self.replay_script = {}
		self.replay = False
		self.sending_replay_script = False
		self.locked = False
		self.spectators = 0
		self.mutelist = {}

