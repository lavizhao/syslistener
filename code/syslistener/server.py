#!/usr/bin/python3

import socket
import sys
import chardet

#host = 'localhost'
host = '0.0.0.0'
port = 514

data_payload = 2048

backlog = 5

f = open("data.txt","w")

if __name__ == '__main__':
    print("您好")

    #creat tcp port
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    #make reuse
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

    server_address = (host,port)

    #start binding
    sock.bind(server_address)

    #sock.listen(backlog)

    while True:
        print("waiting to receive...")
        #client,address = sock.accept()
        
        #data = client.recv(data_payload)

        data,addr = sock.recvfrom(data_payload)

        if data:
            #data 是 bytes
            data = str(data, encoding = "gbk")
            print(data)
            f.write(data+"\n")
