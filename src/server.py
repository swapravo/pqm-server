import multiprocessing
import socket

import src.shutdown
import src.requests
import src.db


class Server():
	def __init__(self, hostname, port):
		self.hostname = hostname
		self.port = port

	def start(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.hostname, self.port))
		self.socket.listen(1)

		while True:

			conn, address = self.socket.accept()
			client = address[0] + ':' + str(address[1])

			if src.db.blacklist.exists(client):
				 # if a specific instance on this (IP : PORT) is misbehaving
				conn.shutdown(socket.SHUT_RDWR)
				conn.close()

			elif src.db.authenticated_clients.exists(client):
				"""
				 if a client on this (IP : PORT) got disconnected somehow and
				 wants to reconnect now
				"""
				process = multiprocessing.Process(target=src.requests.reconnect, args=(conn,))
				process.daemon = True
				process.start()

			elif src.db.blacklist.exists(address[0]):
				"""
				if a client has launched multiple instances from (IP : XXXX) and
				is misbehaving
				"""
				conn.shutdown(socket.SHUT_RDWR)
				conn.close()

			else:
				# if it is a new client trying to connect to the sevice
				process = multiprocessing.Process(target=src.requests.authenticte, args=(conn,))
				process.daemon = True
				process.start()


def main():
	server_ = Server("0.0.0.0", 9000)
	try:
		server_.start()
	finally:
		src.shutdown.shutdown()
		for process in multiprocessing.active_children():
			print("Shutting down process: ", process)
			process.terminate()
			process.join()
		# shutdown background threads.
	print("All done")
