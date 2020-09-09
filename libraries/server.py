import multiprocessing
import socket


class Server(object):

	def __init__(self, hostname, port):

		self.logger = getLogger("server")
		self.hostname = hostname
		self.port = port

	def start(self):

		self.logger.debug("listening")
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((self.hostname, self.port))
		self.socket.listen(1)

		while True:

			conn, address = self.socket.accept()
			#conn.setblocking(True)
			#print("\nconnection: ", conn)
			#print("address: ", address)

			# checking it in this particular order is important
			# assmuming address = (IP, port)

			client = address[0]+':'+str(address[1])

			if blacklist.exists(client):
				self.logger.debug("Dropping connection from: ", address)
				conn.shutdown(SHUT_RDWR)
				conn.close()

			elif client_data := authenticated_clients.exists(client):
				self.logger.debug("Got connection!")
				process = multiprocessing.Process(target=handler, args=(conn, True))
				process.daemon = True
				process.start()
				self.logger.debug("Started process %r", process)

			elif blacklist.exists(address[0]):
				self.logger.debug("Dropping connection from: ", address)
				conn.shutdown(SHUT_RDWR)
				conn.close()

			else:
				self.logger.debug("Got connection!")
				process = multiprocessing.Process(target=handler, args=(conn, False))
				process.daemon = True
				process.start()


basicConfig(level=DEBUG)
server_ = Server("0.0.0.0", 9000)

try:

	info("Listening")
	server_.start()

except:

	exception("Unexpected exception")

finally:

	info("Shutting down")

	exec(shutdown)

	for process in multiprocessing.active_children():
		info("Shutting down process: ", process)
		process.terminate()
		process.join()

	# shutdown background threads.

info("All done")
