import src.globals
import src.network
import src.crypto
import src.utils
import src.shutdown


def username_availability_check(connection, request):

	"""
	STRUCTURE OF THE RESPONSE
	response = {

		"token": {
			"type": string "hash", this response is NOT signed (for now)
				as only a limited number of messages can be signed
				with a single key and keys are hard to generate

			"token": bytes, hash of response["response"]
			}

		"response": -> serialised and asymmetrically encrypted with the key that was sent to the server
			{
			"nonce": the same nonce that was sent to the server by the client
			"response": src.globals.USERNAME_FOUND or src.globals.USERNAME_NOT_FOUND
			}
		}
	"""

	ip, port = connection.getpeername()

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
			isinstance(request["username"], str) and
			src.utils.username_is_vailid(request["username"]) and
			isinstance(request["rolling_public_key"], bytes) and
			src.crypto.key_is_valid(request["rolling_public_key"])):

			print("Malformed Username availability check request: datatype mismatch!")
			src.network.block(connection, src.globals.STRANGER_TTL, True)
			src.shutdown.process()
	except:
		print("Malformed Username availability check request: Dictionary Key Eror!")
		src.network.block(connection, src.globals.STRANGER_TTL, True)
		src.shutdown.process()

	response, err = src.db.username_is_available(request["username"])
	if err:
		print("Username availability Check Error!")
		src.network.close(connection)
		src.shutdown.process()

	# pack and send this response to the client
	response = { \
		"nonce": request["nonce"], \
		"response": response}

	response, err = src.crypto.asymmetrically_encrypt(src.utils.pack(response), \
		request["rolling_public_key"])
	if err:
		src.network.close(connection)
		src.shutdown.process()

	#print(response, err)

	response = src.utils.pack({ \
		"token": { \
			"type": src.globals.HASH", \
			"token": src.crypto.hash(response)}, \
		"response": response})

	response = src.utils.sizeof(response) + response

	#print("SIZEOF RESPONSE: ", len(response)-4)
	#print("username availability check response:")
	# insert timeout here!
	connection.send(response)
	print("Processed a username avail request!")


def signup(connection, request):

	"""
	STRUCTURE OF THE RESPONSE
	response = -> This is serialised and sent over to the client	{

		"token": {
			"type": "sign", string
			"token": bytes, signature of the hash of request["request"]
			}

		"response": -> This serialised and asymmetrically encrypted with the client's keys	{
			"nonce": bytes, of length src.globals.HASH_SIZE # 2
			"response": src.globals.SIGNUP_SUCCESSFUL or src.globals.SIGNUP_UNSUCCESSFUL
			}
		}

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
			isinstance(request["username"], str) and
			src.utils.username_is_vailid(request["username"]) and
			isinstance(request["encryption_public_key"], bytes) and
			src.crypto.key_is_valid(request["encryption_public_key"]) and
			isinstance(request["signature_public_key"], bytes) and
			src.crypto.key_is_valid(request["signature_public_key"])):

			print("Malformed Signup request: Datatype error!")
			src.network.block(connection, src.globals.HOUR)
			src.shutdown.process()
	except:
		print("Malformed Signup request: Dictionary key error!")
		src.network.block(connection, src.globals.HOUR)
		src.shutdown.process()

	out, err = src.db.username_is_available(request["username"])
	if err:
		print("Username availability Check Error!")
		src.network.close(connection)
		src.shutdown.process()

	if out == src.globals.USERNAME_NOT_FOUND:

		src.db.add_user(request["username"], request["encryption_public_key"], \
			request["signature_public_key"])
		# SHOULD I INSERT A CHECK HERE?

		response = { \
			"nonce": request["nonce"], \
			"response": src.globals.SIGNUP_SUCCESSFUL}

		response, err = src.crypto.asymmetrically_encrypt(src.utils.pack(response), \
			request["encryption_public_key"])
		if err:
			src.network.close(connection)
			src.shutdown.process()

		out, err = src.crypto.sign(src.crypto.hash(response), request["username"])
		if err:
			print("Signature Error")
			src.network.close(connection)
			src.shutdown.process

		# PLAIN HASHES HERE AND NOT SIGNED ONES
		response = src.utils.pack({ \
			"token": { \
				"type": src.globals.SIGN, \
				"token": out}, \
			"response": response})

		#print("SIZEOF RESPONSE: ", len(response))
		#print(response)

		response = src.utils.sizeof(response) + response
		# insert timeout here!
		connection.send(response)

		print("SIGNUP PROCESSED SUCCESSFULLY!")

	else:
		print("Blocking user for crafting signup request for an unavailable username!")
		src.network.block(connection, src.globals.HOUR)
		src.shutdown.process()


def login(connection, request):

	"""
	STRUCTURE OF A REQUEST
	request = {
		"username": utf-8 string
		"token": bytes, SIGNED WHAT???}
	"""

	"""
		elif recieved_request == src.globals.LOGIN_STEP_1:
			print("IN LOGIN STEP 1")

			# WRIITE SIGNATURE PUB KEY TO CURRENT .ccr file
			if src.utils.username_is_vailid(plaintext["username"]):
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


	pass


def reconnect(connection, request):
	pass


def process(connection):

	ip, port = connection.getpeername()
	port = str(port)

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
				src.shutdown.process()

		"""
		STRUCTURE OF A REQUEST
		request = {
			version: str, version of the client
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
			if not (
				isinstance(request["version"], str) and
				(request["token"]["type"] == src.globals.HASH or
				request["token"]["type"] == src.globals.SIGN) and
				isinstance(request["request"], bytes)):

				print("Malformed request: Datatype Error!")
				src.network.block(connection, src.globals.HOUR, block_ip_and_port=True)
				src.shutdown.process()

		except:
			print("Malformed request: Dictionary key error!")
			src.network.block(connection, src.globals.HOUR, block_ip_and_port=True)
			src.shutdown.process()

		# try except key error return
		# and handle version specific stuff!
		if request["version"] not in src.globals.SUPPORTED_VERSIONS:
			connection.send(src.globals.UNSUPPORTED_VERSION)
			src.network.close(connection)
			src.shutdown.process()

		token = request["token"]
		if token["type"] == src.globals.HASH:
			if src.crypto.hash(request["request"]) != token["token"]:
				# hash verification FAILED
				src.network.close(connection)
				src.shutdown.process()

		request, err = src.crypto.asymmetrically_decrypt(request["request"], src.globals.SERVER)
		if err:
			src.network.close(connection)
			src.shutdown.process()

		if isinstance(request, bytes):
			request = src.utils.unpack(request)
			if not request or not isinstance(request, dict):
				src.network.close(connection)
				src.shutdown.process()
		else:
			src.network.close(connection)
			src.shutdown.process()

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
			if not (len(request["timestamp"]) == 4 and
				# and request_code is a valid code
				isinstance(request["request_code"], bytes) and
				len(request["request_code"]) == 2 and
				isinstance(request["nonce"], bytes) and
				len(request["nonce"]) == src.globals.NONCE_SIZE and
				isinstance(request["request"], dict)):

				#print("Inner request 1 error!")
				src.network.block(connection, src.globals.HOUR, block_ip_and_port=True)
				src.shutdown.process()

		except:
			src.network.block(connection, src.globals.HOUR, block_ip_and_port=True)
			src.shutdown.process()

		if src.utils.timedelta(src.utils.timestamp(), request["timestamp"]) > \
			src.globals.MAX_ALLOWABLE_TIME_DELTA or src.db.nonces.exists(request["nonce"]):

			# should i block this user for a few minutes
			# or just close the connection
			# Or should i block this IP instead?
			# print("Timeout error!")
			src.network.block(ip+':'+port, src.globals.MAX_ALLOWABLE_TIME_DELTA)
			src.shutdown.process()

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
			src.network.block(connection, src.globals.STRANGER_TTL)
			src.shutdown.process()
