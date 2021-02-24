from math import abs

import src.requests
import src.network
import src.utils
import src.crypto
import src.db
import src.globals


# requests routed through this method are asymmetrically encrypted
def unauthenticated_client_handler(connection):

	ip, port = src.network.ip_port(connection)

	# THROTTLE REQUESTS
	# PREFERABLY FROM THE src.network.recieve fn

	while True:
		request = src.network.recieve(connection, src.globals.DMZ_BUFFER_SIZE)
		if request:
			# feeding dmz data straight to this function
			# is that safe?
			request = src.utils.unpack(request)
			if not request or not isinstance(request, dict):
				print("Unpacking FAILED")
				src.network.close(connection)
		else:
			src.network.close(connection)

		"""
		STRUCTURE OF A REQUEST
		request = {
			version: str, version of the client
			token: dict = {
							"type": str, a "hash" or a "sign" (signed hash),
							"token": bytes }
					## NOTE: we have to allow unsigned hashes because
					creating such a signature needs keys, generating which
					are computationally hard
			request: bytes, asymmetrically encrypted, actual request }
		"""

		try:
			if not (
				isinstance(request["version"], str) and
				(request["token"]["type"] == src.globals.HASH or
				request["token"]["type"] == src.globals.SIGN) and
				isinstance(request["request"], bytes)):

				print("Malformed request: Datatype Error!")
				src.network.block(connection, src.globals.HOUR)
		except:
			print("Malformed request: Dictionary key error!")
			# this will happen iff someone modifies the source to add/remove
			# dictionary field/value pairs
			src.network.block(connection, src.globals.HOUR)

		# try except key error return
		# and handle version specific stuff!
		if request["version"] not in src.globals.SUPPORTED_VERSIONS:
			connection.send(src.globals.UNSUPPORTED_VERSION)
			src.network.close(connection)

		token = request["token"]
		if token["type"] == src.globals.HASH:
			if src.crypto.hash(request["request"]) != token["token"]:
				# hash verification FAILED
				src.network.close(connection)

		request, err = src.crypto.asymmetrically_decrypt(request["request"], \
			src.globals.SERVER)
		if err:
			src.network.close(connection)

		if isinstance(request, bytes):
			request = src.utils.unpack(request)
			if not isinstance(request, dict):
				src.network.close(connection)
		else:
			src.network.close(connection)

		"""
		STRUCTURE OF THE INNER REQUEST
			request = {
				timestamp: bytes, an UNIX timestamp
				nonce: bytes
				request_code: bytes, a src.globals code
				request: dict, contains all necessary info to perfom the request
					}
		"""
		try:
			if not (isinstance(request["timestamp"], int) and
				# and request_code is a valid code
				isinstance(request["request_code"], bytes) and
				len(request["request_code"]) == 2 and
				isinstance(request["nonce"], bytes) and
				len(request["nonce"]) == src.globals.NONCE_SIZE and
				isinstance(request["request"], dict)):

				#print("Inner request 1 error!")
				src.network.block(connection, src.globals.HOUR)

		except:
			src.network.block(connection, src.globals.HOUR)

		if abs(src.utils.timestamp() - request["timestamp"]) > \
			src.globals.MAX_ALLOWABLE_TIME_DELTA or \
			src.db.nonces.exists(request["nonce"]):
			# should i block this (user?) for a few minutes
			# or just close the connection
			# Or should i block this IP instead?
			# print("Timeout error!")
			src.network.block(ip, src.globals.MAX_ALLOWABLE_TIME_DELTA)

		src.db.nonces.set(request["nonce"], 0, \
			ex=src.globals.MAX_ALLOWABLE_TIME_DELTA)
		request["request"]["nonce"] = request["nonce"]

		if request["request_code"] == src.globals.USERNAME_AVAILABILITY_CHECK:
			src.requests.username_availability_check(connection, \
				request["request"])

		elif request["request_code"] == src.globals.SIGNUP:
			src.requests.signup(connection, request["request"])

		elif request["request_code"] == src.globals.LOGIN_STEP_1:
			request["token"] = token["token"]
			src.requests.login(connection, request["request"])

		elif request["request_code"] == src.globals.RECONNECT:
			src.requests.reconnect(connection, request["request"])

		else:
			src.network.block(connection, src.globals.STRANGER_TTL)

	# check if the user exists in the blacklist


"""
REQUESTS ROUTED THROUGH THIS METHOD ARE SYMMETRICALLY ENCRYPTED
THIS METHOD DOES THE SENDING/RECIEVING, SYMMETRIC ENCRYPTION/DECRYPTION
"""

def authenticated_client_handler(connection, session_ID):

	message_ID = 0
	# password = fetch password from redis here using the session_ID
	password = ''

	while True:
		request = src.network.recieve(connection, src.globals.DMZ_BUFFER_SIZE)

		# surround this in a try:

		if request:
			request = src.crypto.symmetrically_decrypt(request, password)
			if request is None:
				src.network.close(connection)
			# feeding dmz data straight to this function
			# is that safe?
			request = src.utils.unpack(request)
			if not isinstance(request, dict):
				print("Unpacking FAILED")
				src.network.close(connection)

			# validate message here
			if not (request["session_ID"] == session_ID and \
				request["message_id"] == message_ID and \
				src.utils.timedelta(src.utils.timestamp(), request["timestamp"]) \
					< src.globals.MAX_ALLOWABLE_TIME_DELTA and
				isinstance(request["request_code"], bytes) and
				len(request["request_code"]) == 2 and
				"request" in request):

				print("Invalid message!")
				src.network.close(connection)

		# check if this statement skips blank requests
		# BUT THAT WONT QUIT THE PROCESS!!!!
		# heartbeats for the client???
		else:
			# if it is a blank request, then skip it
			continue

		message_ID += 1

		# was thinking of having a hash set (constant time) containing all
		# possible requests in place of a chain of if elses...
		# look into which requests send data back, encrypt it
		# and send it back
		if request["request_code"] == src.globals.GET_PUBLIC_KEYS:
			response, err = src.requests.fetch_keys(connection, request["request"])
		elif request["request_code"] == src.globals.UPDATE_MAILBOX:
			response = src.requests.update_mailbox(connection)
		elif request["request_code"] == src.globals.SYNC_MAILBOX:
			response = src.requests.sync_mailbox(connection)
		elif request["request_code"] == src.globals.SEND_MAIL:
			response = src.requests.send_mail(connection, request["request"])
		elif request["request_code"] == src.globals.DELETE_MAIL:
			response = src.requests.delete_mail(connection, request["request"])
		elif request["request_code"] == src.globals.DELETE_ACCOUNT:
			response = src.requests.delete_account(connection, request["request"])
		else:
			src.network.block(connection, src.globals.HOUR)
