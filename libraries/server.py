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
		self.socket.bind((self.hostname, self.port))
		self.socket.listen(1)

		while True:

			conn, address = self.socket.accept()

			if blocked_ips.exists(ip(conn)):
				self.logger.debug("Dropping connection from: ", ip(conn))
				conn.shutdown(SHUT_RDWR)
				conn.close()

			self.logger.debug("Got connection!")
			process = multiprocessing.Process(target=handler, args=(conn, address))
			process.daemon = True
			process.start()
			self.logger.debug("Started process %r", process)



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
