import socket

"""
This module is a simple wrapper around the socket library. 
It can be used anywhere in the entire project
"""
class Skt:

    # Function to initialize a socket object
    def __init__(self,own_host:str, own_port:int):
        self.host = own_host
        self.port = own_port
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.skt.bind((self.host, self.port))
    
    # Function to get the socket object
    def get_socket(self):
        return self.skt
    
    # Sending data thru the socket
    def send_data(self, data:str):
        self.skt.sendall(data)
    
    # Connecting to remote socket
    def remote_connect(self, remote_host:str, remote_port:int):
        self.skt.connect((remote_host,remote_port))
    
    # Receive all the data at once
    # TODO: Add a return type
    def recv_data(self):
        fragments = []
        while True: 
            chunk = self.skt.recv(1024)
            if not chunk: 
                break
            fragments.append(chunk)
        arr = b''.join(fragments)
        return arr

    # Function to close the socket object
    def close(self):
        self.skt.close()