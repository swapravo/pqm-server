from socket import SHUT_RDWR

import src.db


def close(connection):
	connection.shutdown(SHUT_RDWR)
	connection.close()
	src.shutdown.process()


def recieve(connection, max_payload_size):

	if max_payload_size == 0:
		close(connection)
		src.shutdown.process()

	payload_size = int.from_bytes(connection.recv(4), byteorder='little')

	if payload_size == 0:
		print("Dropping Undersized request!")
		close(connection)
		src.shutdown.process()

	elif payload_size > max_payload_size:
		print("Dropping Oversized request!")
		close(connection)
		src.shutdown.process()

	data = bytearray(payload_size)
	pos = 0
	total_recieved = 0
	buffer_size = 4096

	while pos < payload_size:
		chunk = connection.recv(buffer_size)
		chunk_size = len(chunk)
		total_recieved += chunk_size

		data[pos:pos+chunk_size] = chunk
		pos += chunk_size

		if total_recieved == payload_size:
			return data


def send(connection, data):
	try:
		connection.sendall(data)
	except:
		return 1
		# press xxx to retry


def ip_port(connection):
	_ip, _port = connection.getpeername()[0]
	return (_ip, str(_port))
