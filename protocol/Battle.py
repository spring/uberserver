
class Battle():
	def __init__(self, root, id, type, natType, password, port, maxplayers,
						hashcode, rank, maphash, map, title, modname,
						passworded, host, users):

		self._root = root
		self.id = id #name
		self.passworded = passworded #key
		self.password = password #key
		self.users = users #users (set) # list with all session_ids of joined users
		self.host = host #founder # client.session_id
		self.mutelist = {} #mutelist

		self.title = title
		self.engine = ''
		self.version = ''
		self.modname = modname
		self.map = map
		self.maxplayers = maxplayers

		self.hashcode = hashcode
		self.maphash = maphash

		self.type = type
		self.locked = False
		self.rank = rank
		self.bots = {}
		self.script_tags = {}
		self.startrects = {}
		self.disabled_units = []
		self.port = port
		self.natType = natType

		self.replay_script = {}
		self.replay = False
		self.sending_replay_script = False

		self.pending_users = set() #users who requested to join, but haven't heard back from the host yet
		self.spectators = 0 # duplicated info?



