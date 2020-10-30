import src.globals
import src.network
import src.crypto


def username_availability_check(connection, request):

	ip, port = connection.getsockname()

	"""
	STRUCTURE OF THE REQUEST
	request = {
		nonce: bytes
		username: utf-8 string
		rolling_public_key: bytes, a one time public key
			}
	"""

	try:
		if not (
			instanceof(request["username"], str) and
			src.utils.username_validity_checker(request["username"]) and
			instanceof(request["rolling_public_key"], bytes) and
			src.crypto.validate_key(request["rolling_public_key"])):

			src.network.block(connection)
			return
			# kill process here
	except:
		src.network.block(connection)
		return
		# kill process here

	response = src.db.is_username_available(request["username"])

	# pack and send this response to the client
	response = {"nonce": request["nonce"], "response": response}

	response = src.crypto.asymmetrically_encrypt(src.utils.pack(response), request["rolling_public_key"])

	response = src.utils.pack({"token": src.crypto.hash(response), "response": response})
	response = (len(response)).to_bytes(4, byteorder='little') + response

	# insert timeout here!
	connection.sendall(response)

	print("USERNAME_AVAILABILITY_CHECK PROCESSED SUCCESSFULLY!")


def signup(connection, request):

	"""
	STRUCTURE OF THE REQUEST
	request = {
		nonce: bytes
		username: utf-8 string
		encryption_public_key: bytes
		signature_public_key: bytes
			}
	"""

	try:
		if not (
			instanceof(request["username"], str) and
			src.utils.username_validity_checker(request["username"]) and
			instanceof(request["encryption_public_key"], bytes) and
			src.crypto.validate_key(request["encryption_public_key"]) and
			instanceof(request["signature_public_key"], bytes) and
			src.crypto.validate_key(request["signature_public_key"])):

			src.network.block(connection)
			return
			# kill process here
	except:
		src.network.block(connection)
		return
		# kill process here

	if src.db.is_username_available(request["username"]) == src.globals.USERNAME_NOT_FOUND:

		src.db.signup_user(request["username"], request["encryption_public_key"], request["signature_public_key"])
		# SHOULD I INSERT A CHECK HERE?

		response = {"nonce": nonce, "response": src.globals.SIGNUP_SUCCESSFUL}

		response = src.crypto.asymmetrically_encrypt(src.utils.pack(response), request["encryption_public_key"])

		# PLAIN HASHES HERE AND NOT SIGNED ONES
		response = src.utils.pack({"token": src.crypto.sign(src.crypto.hash(response), request["username"]), "response": response})
		response = (len(response)).to_bytes(4, byteorder='little') + response

		# insert timeout here!
		connection.sendall(response)

		print("SIGNUP PROCESSED SUCCESSFULLY!")

	else:
		src.network.block(connection, src.globals.HOUR)


def login(connection, request):

	"""
	STRUCTURE OF A REQUEST
	request = {
		"username": utf-8 string
		"token": bytes, SIGNED WHAT???

	}
	"""

	pass


def reconnect(connection, request):
	pass


def process(connection):

	# THROTTLE REQUESTS
	# PREFERABLY FROM THE src.network.recieve fn

	while True:
		request = src.network.recieve(connection, src.globals.DMZ_BUFFER_SIZE)
		if request:
			# feeding dmz data straight to this function
			# is that safe?
			request = src.utils.unpack(request)
			if not instanceof(request, bytes):
				src.network.close(connection)
				return
				# kill process here

	"""
	STRUCTURE OF A REQUEST
	request = {
		version: int, version of the client
		token: dict = {
						"type": str, a "hash" or a "sign"ed hash,
						"token": bytes }
				## NOTE: we have to allow unsigned hashes because
				creating such a signature needs keys, generating which
				are computationally hard
		request: bytes, asymmetrically encrypted, actual request }
	"""

	# validating supplied data here
	try:
		if not (instanceof(request["vesion"], int) and
			(request["token"]["type"] == "hash" or
			request["token"]["type"] == "sign") and
			instanceof(request["request"], bytes)):
			src.network.block(connection)
			return
			# kill process here
	except:
		src.network.block(connection)
		return
		# kill process here

	# try except key error return
	# and handle version specific stuff!
	if request["version"] not in src.globals.SUPPORTED_VERSIONS:
		connection.sendall(src.globals.UNSUPPORTED_VERSION)
		src.network.close(connection)
		return
		# kill process here

	token = request["token"]
	if token["type"] == "hash":
		if src.crypto.hash(request) != token["token"]:
			# hash verification FAILED
			src.network.close(connection)
			# kill process here
			return

	request = src.crypto.asymmetrically_decrypt(request["request"])

	if isinstance(request, bytes):
		request = src.utils.unpack(request)
		if not instanceof(request, dict):
			src.network.close(connection)
			# kill process here
			return
	else:
		src.network.close(connection)
		# kill process here
		return

	"""
	STRUCTURE OF THE INNER REQUEST
		request = {
			timestamp: bytes, an UNIX timestamp
			request_code: bytes, a src.globals code
			nonce: bytes
			request: dict, contains all necessary info to perfom the request
				}
	"""

	try:
		if not (len(request["timestamp"]) == 4 and
			# and request_code is a valid code
			instanceof(request["request_code"], bytes) and
			 len(request["request_code"]) == 2 and
			instanceof(request["request_code"], bytes) and
			len(request["request_code"]) == sc.globals.NONCE_SIZE and
			instanceof(request["request"], dict)):
			src.network.block(connection)
			return
			# kill process here
	except:
		src.network.block(connection)
		return
		# kill process here

	if src.utils.timedelta(src.utils.timestamp(), request["timestamp"]) > \
		src.globals.MAX_ALLOWABLE_TIME_DELTA or src.db.nonces.exists(request["nonce"]):

		# should i block this user for a few minutes
		# or just close the connection
		# Or should i block this IP instead?
		src.network.block(ip+':'+port, src.globals.MAX_ALLOWABLE_TIME_DELTA)
		return

	src.db.nonces.set(request["nonce"], 0, ex=src.globals.MAX_ALLOWABLE_TIME_DELTA)
	request["request"]["nonce"] = request["nonce"]

	if request["request_code"] == src.globals.USERNAME_AVAILABILITY_CHECK:
		src.requests.username_availability_check(connection, request["request"])

	elif request["request_code"] == src.globals.SIGNUP:
		src.requests.signup(connection, request["request"])

	elif request["request_code"] == src.globals.LOGIN_STEP_1:
		request["token"] = token["token"]
		src.requests.login(connection, request["request"])

	elif request["request_code"] == src.globals.RECONNECT:
		src.requests.reconnect(connection, request["request"])

	else:
		src.network.block(connection)
		return
		# kill process here


"""
		elif recieved_request == src.globals.LOGIN_STEP_1:
			print("IN LOGIN STEP 1")

			# WRIITE SIGNATURE PUB KEY TO CURRENT .ccr file
			if src.utils.username_validity_checker(plaintext["username"]):
				src.network.block(ip+':'+port, src.globals.HOUR)
				returnUSERNAME_AVAILABILITY_CHECK

			if src.utils.username_availability != src.globals.USERNAME_FOUND:
				src.network.block(ip+':'+port, src.globals.HOUR)
				return

			encryption_key, signature_key = src.db.fetch_keys(plaintext["username"])

			src.insert_public_key(encryption_key, src.crypto.encryption_key(username))
			src.insert_public_key(signature_key, src.crypto.signature_key(username))

			if src.crypto.verify_signature(signature):
				src.network.block(ip+':'+port, src.globals.HOUR)
				return

			message = {"nonce": plaintext["nonce"], "response_code": okay_code}

			src.crypto.asymmetrically_respond(connection, message, encryption_key, plaintext["username"])
			continue


		elif recieved_request == src.globals.LOGIN_STEP_2:
			print("IN LOGIN STEP 2")
			#user = message["user_id"]
			#signature = message["signature"]
			#fetch user's sig pub key and validate signature

			if src.crypto.verify_signature(signature_public_key, signature):
				message = {"nonce": plaintext["nonce"], "response_code": okay_code}
				random_name = src.utils.random_name_generator()
				src.crypto.asymmetrically_respond(connection, message, random_name)
				continue
			else:
				src.network.block(ip, src.globals.HOUR)
				return
		else:
			# LOOKS LIKE SOMEONE IS SENDING WRONG REQUEST CODES
			src.network.block(ip+':'+port, src.globals.MAX_ALLOWABLE_TIME_DELTA)
			return

	except:
		print("Exception while handling request!")

	finally:
		print("Closing socket")
		connection.close()
"""
