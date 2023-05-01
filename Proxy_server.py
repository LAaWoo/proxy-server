from socket import *
import sys

if len(sys.argv) <= -100:
    print('Usage : "python ProxyServer.py server_ip"\n[server_ip : It is the IP Address Of Proxy Server')
    sys.exit(2)

# Create a server socket, bind it to a port and start listening
tcpSerSock = socket(AF_INET, SOCK_STREAM)
localhost = "192.168.1.160"
tcpSerSock.bind((localhost, 12003))
tcpSerSock.listen(5)

while 1:
    # Strat receiving data from the client
    print('Ready to serve...')
    tcpCliSock, addr = tcpSerSock.accept()
    print('Received a connection from:', addr)
    message = tcpCliSock.recv(1024).decode('utf-8')

    if message.split()[1] == None:
        continue
    if message.split()[1] != '/http://www.gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file3.html':
        continue
    if message.split()[1] == '/favicon.ico':
        continue

    print(message)
    # Extract the filename from the given message
    print(message.split()[1])
    filename = message.split()[1].partition("/")[2]
    print(filename)
    fileExist = "false"
    filetouse = "/" + filename
    print(filetouse)
    try:
        # Check wether the file exist in the cache
        f = open(filetouse[1:], "r")
        outputdata = f.readlines()
        fileExist = "true"
        print("Requested file found in cache:", filetouse)
        # ProxyServer finds a cache hit and generates a response message
        tcpCliSock.send("HTTP/1.0 200 OK\r\n\r\n".encode())
        tcpCliSock.send("Content-Type:text/html\r\n".encode())
        for i in range(0, len(outputdata)):
            tcpCliSock.send(outputdata[i].encode())
            tcpCliSock.send("\r\n".encode())

            tcpCliSock.close()
            print('Read from cache')
        # Error handling for file not found in cache
    except IOError:
        if fileExist == "false":
            print("Requested file NOT found in cache, perform GET to server for file:", filetouse)
            # Create a socket on the proxyserver
            c = socket(AF_INET, SOCK_STREAM)
            hostn = filename.replace("www.", "", 1)
            print(hostn)
            try:
                # Connect to the socket to port 80
                c.connect((hostn, 80))
                # Create a temporary file on this socket and ask port 80 for the file requested by the client
                buff="GET"+' / '+" HTTP/1.1\r\n\r\n"
                c.send(buff.encode())
                recv = c.recv(15000)
                tmpFile = open("./"+filename, "wb")
                tmpFile.write(recv)
                print("Saved successfully")
                tcpCliSock.send(recv)
                # Read the response into buffer

                # Create a new file in the cache for the requested file. Also send the response in the buffer to client socket and the corresponding file in the cache

            except :
                print("Illegal request")
        else:
            # HTTP response message for file not found
            tcpCliSock.send("HTTP/1.0 404 sendErrorErrorError\r\n".encode())
            tcpCliSock.send("Content-Type:text/html\r\n".encode())
            tcpCliSock.send("\r\n".encode())
    # Close the client and the server sockets
    tcpCliSock.close()
tcpSerSock.close()
