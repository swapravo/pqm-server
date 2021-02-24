from multiprocessing import Process
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, SHUT_RDWR, socket

import src.shutdown
import src.db.blacklist
import src.client


class Server():
	def __init__(self, hostname, port):
		self.hostname = hostname
		self.port = port

	def start(self):
		self.socket = socket(AF_INET, SOCK_STREAM)
		self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.socket.bind((self.hostname, self.port))
		self.socket.listen(1)

		while True:
			connection, address = self.socket.accept()
			client_ip = address[0]
			print("\nNew connection: ", client_ip, '\n')

			if blacklist.exists(client_ip):
				# if a specific instance on this IP is misbehaving
				connection.shutdown(SHUT_RDWR)
				connection.close()
			else:
				# if it is a new client trying to connect to the sevice
				process = Process(target=\
					src.client.unauthenticated_client_handler, \
					args=(connection,))
				process.daemon = True
				process.start()


def main():
	server_ = Server("0.0.0.0", 9000)
	try:
		server_.start()
	finally:
		src.shutdown.server()
	print("All done")
