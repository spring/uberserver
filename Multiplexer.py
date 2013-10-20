import time
from select import * # eww hack but saves the other hack of selectively importing constants

class EpollMultiplexer:

	def __init__(self):
		self.args = []
		self.filenoToSocket = {}
		self.socketToFileno = {}
		self.sockets = set([])
		self.output = set([])
		self.args = []

		self.inMask = EPOLLIN | EPOLLPRI
		self.outMask = EPOLLOUT
		self.errMask = EPOLLERR | EPOLLHUP

		self.poller = epoll()

	def register(self, fd):
		fd.setblocking(0)
		self.sockets.add(fd)
		fileno = fd.fileno()
		self.filenoToSocket[fileno] = fd
		self.socketToFileno[fd] = fileno # gotta maintain this because fileno() lookups aren't possible on closed sockets
		self.poller.register(fileno, self.inMask | self.errMask)

	def unregister(self, fd):
		if fd in self.sockets:
			self.sockets.remove(fd)
		if fd in self.output:
			self.output.remove(fd)
		fileno = self.socketToFileno[fd]
		self.poller.unregister(fileno)
		del self.socketToFileno[fd]
		del self.filenoToSocket[fileno]

	def setoutput(self, fd, ready):
		# this if structure means it only scans output once.
		if not ready and fd in self.output:
			self.output.remove(fd)
		elif ready and fd in self.sockets:
			self.output.add(fd)
		if not fd in self.socketToFileno: return
		eventmask = self.inMask | self.errMask | (self.outMask if ready else 0)
		self.poller.modify(fd, eventmask) # not valid for select.poll before python 2.6, might need to replace with register() in this context

	def pump(self, callback):
		while True:
			inputs, outputs, errors = self.poll()
			callback(inputs, outputs, errors)

	def poll(self):
		for i in xrange(5):
			try:
				results = self.poller.poll(*self.args)
			except IOError, e:
				if e[0] == 4:
					# interrupted system call - this happens when any signal is triggered
					continue
				else:
					raise e
			break

		inputs = []
		outputs = []
		errors = []

		for fd, mask in results:
			s = self.filenoToSocket[fd]
			if mask & self.inMask: inputs.append(s)
			if mask & self.outMask: outputs.append(s)
			if mask & self.errMask: errors.append(s)
		return inputs, outputs, errors

