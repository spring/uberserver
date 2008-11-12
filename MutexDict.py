import thread
# automagic mutex locking dictionary :D

# todo:
# I could probably make it detect a finished iteration and unlock properly
class MutexDict:
	def __init__(self, dict=None, **kwargs):
		self.mutex = thread.allocate_lock()
		self.lock_id = -1
		self.data = {}
		if dict is not None:
			self.update(dict)
		if len(kwargs):
			self.update(kwargs)
	
	def __repr__(self, lock=None):
		lock = self.lock(lock)
		data = repr(self.data)
		self.unlock(lock)
		return data
	
	def __cmp__(self, dict, lock=None):
		lock = self.lock(lock)
		if isinstance(dict, UserDict):
			data = cmp(self.data, dict.data)
		else:
			data = cmp(self.data, dict)
		self.unlock(lock)
		return data
	
	def __len__(self, lock=None):
		lock = self.lock(lock)
		data = len(self.data)
		self.unlock(lock)
		return len
	
	def __getitem__(self, key, lock=None):
		lock = self.lock(lock)
		data = None
		if key in self.data:
			data = self.data[key]
		if hasattr(self.__class__, "__missing__"):
			data = self.__class__.__missing__(self, key)
		self.unlock(lock)
		if data: return data
		raise KeyError(key)
	
	def __setitem__(self, key, item, lock=None):
		lock = self.lock(lock)
		self.data[key] = item
		self.unlock(lock)
	
	def __delitem__(self, key, lock=None):
		lock = self.lock(lock)
		del self.data[key]
		self.unlock(lock)
	
	def clear(self, lock=None):
		lock = self.lock(lock)
		self.data.clear()
		self.unlock(lock)
	
	def copy(self, lock=None):
		lock = self.lock(lock)
		if self.__class__ is UserDict:
			data = self.data.copy()
			self.unlock(lock)
			return UserDict(data)
		import copy
		data = self.data
		try:
			self.data = {}
			c = copy.copy(self)
		finally:
			self.data = data
		c.update(self)
		self.unlock(lock)
		return c
	
	def keys(self, lock=None):
		lock = self.lock(lock)
		data = self.data.keys()
		self.unlock(lock)
		return data
	
	def items(self, lock=None):
		lock = self.lock(lock)
		data = self.data.items()
		self.unlock(lock)
		return data
	
	def iteritems(self, lock=None):
		lock = self.lock(lock)
		data = self.data.iteritems()
		self.unlock(lock)
		return data
	
	def iterkeys(self, lock=None):
		lock = self.lock(lock)
		data = self.data.iterkeys()
		self.unlock(lock)
		return data
	
	def itervalues(self, lock=None):
		lock = self.lock(lock)
		data = self.data.itervalues()
		self.unlock(lock)
		return data
	
	def values(self, lock=None):
		lock = self.lock(lock)
		data = self.data.values()
		self.unlock(lock)
		return data
	
	def has_key(self, key, lock=None):
		lock = self.lock(lock)
		data = self.data.has_key(key)
		self.unlock(lock)
		return data
	
	def update(self, dict=None, lock=None, **kwargs):
		lock = self.lock(lock)
		if dict is None:
			pass
		elif isinstance(dict, UserDict):
			self.data.update(dict.data)
		elif isinstance(dict, type({})) or not hasattr(dict, 'items'):
			self.data.update(dict)
		else:
			for k, v in dict.items():
				self[k] = v
		if len(kwargs):
			self.data.update(kwargs)
		self.unlock(lock)
	
	def get(self, key, failobj=None, lock=None):
		lock = self.lock(lock)
		if not self.has_key(key):
			data = failobj
		else:
			data = self[key]
		self.unlock(lock)
		return data
	
	def setdefault(self, key, failobj=None, lock=None):
		lock = self.lock(lock)
		if not self.has_key(key):
			self[key] = failobj
		data = self[key]
		self.unlock(lock)
		return data
	
	def pop(self, key, lock=None, *args):
		lock = self.lock(lock)
		data = self.data.pop(key, *args)
		self.unlock(lock)
		return data
	
	def popitem(self, lock=None):
		lock = self.lock(lock)
		data = self.data.popitem()
		self.unlock(lock)
		return data
	
	def __contains__(self, key, lock=None):
		lock = self.lock(lock)
		data = key in self.data
		self.unlock(lock)
		return data
	
	def __iter__(self, lock=None):
		lock = self.lock(lock)
		data = iter(self.data)
		self.unlock(lock)
		return data
	
	def lock(self, lock):
		if lock == self.lock_id: return None # won't release lock since it was already locked properly
		self.mutex.acquire()
		self.lock_id += 1
		return self.lock_id
	
	def unlock(self, lock):
		if lock == self.lock_id:
			self.mutex.release()
		elif not lock: return # calling code already locked it, will not release lock
		else: raise Exception('Mutex attempted to unlock without correct key',self)
	
#	@classmethod
#	def fromkeys(cls, iterable, value=None, lock=None):
#		lock = self.lock(lock)
#		d = cls()
#		for key in iterable:
#			d[key] = value
#		self.unlock(lock)
#		return d
