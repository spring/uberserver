import socket, thread, select, sys, traceback
from Client import Client

class ClientHandler:
    '''This represents one client handler. Threading is recommended. Multiple copies work.'''
    def __init__(self):

        self.input = []
        self.output = []
        self.running = 0
	self.socketmap = {}

    def MainLoop(self):
        self.running = 1
        while self.running:
            try:
                if len(self.input) < 1:
                    self.running = 0
                    continue

                try:
                    inputready,outputready,exceptready = select.select(self.input,self.output,[],1)   # requires timeout so new sockets will be added to the loop without data from other sockets
                except:
                    inputready = []
                    outputready = []

                for s in inputready:
                    try:
                        data = s.recv(1024)
                    except socket.error:
                        s.close()
                        self.input.remove(s)
                        if s in self.output:
                            self.output.remove(s)
                    if data:
			if s in self.socketmap:
				self.socketmap[s].Handle(data)
                    else:
                        print 'Client disconnected from %s, session ID was %s'%(s.getpeername()[0], self.socketmap[s].session_id)
                        self.socketmap[s].Remove()
                        del self.socketmap[s]
                        self.input.remove(s)

                for s in outputready:
                    try:
                        self.socketmap[s].FlushBuffer()
                    except KeyError:
                        if s in self.output:
                            self.output.remove(s)
                        if s in self.input:
                            self.input.remove(s)
                    except socket.error:
                        s.close()
                        if s in self.output:
                            self.output.remove(s)
                        if s in self.input:
                            self.input.remove(s)
                        
            except:
               print '-'*60
               traceback.print_exc(file=sys.stdout)
               print '-'*60

    def AddClient(self, client):
	self.socketmap[client.conn] = client
        if not self.running:
            thread.start_new_thread(self.MainLoop,())
        self.input.append(client.conn)

    def RemoveClient(self, client):
        if client in self.input:
            self.input.remove(client)
