import socket

#socket.SOCK_STREAM indicates TCP
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(("192.168.13.245", 12345))
while(True):
    serversocket.listen(1)

    (   clientsocket, address) = serversocket.accept()
    msg = clientsocket.recv(1024)
    print ("server recieved "+msg)
