# coding=utf-8
import thread, socket
from ClientHandler import ClientHandler
from DataHandler import root
from Client import Client
import ip2country

host = ''
port = 8200
backlog = 100
size = 10240
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host,port))
server.listen(backlog)
input = [server]


curthread = 0
maxthreads = 10
clienthandlers = []
for iter in range(maxthreads):
        clienthandlers.append( ClientHandler() )

_root = root()
session_id = 0

print 'Uberserver BETA starting on port %i'%port
print 'Using %i client handling threads.'%maxthreads

running = 1

clients = {}

def AddClient(client):
	global curthread
        clienthandlers[curthread].AddClient(client)
        clients[client] = curthread
        curthread += 1
        if curthread > len(clienthandlers)-1:
                curthread = 0

def RemoveClient(client):
        threadnum = clients[client]
        clienthandlers[threadnum].RemoveClient(client)

while running:
        connection, address = server.accept()
        country_code = ip2country.lookup(address[0]) # actual flag
        #country_code = ip2country.randomcc() # random flags
        client = Client(_root, clienthandlers[curthread], connection, address, session_id, country_code)
        _root.clients[session_id] = client
        AddClient(client)
        session_id += 1

server.close()
