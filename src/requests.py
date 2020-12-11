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

	except:
		print("Malformed Username availability check request: Dictionary Key Eror!")
		src.network.block(connection, src.globals.STRANGER_TTL, True)

	response, err = src.db.username_is_available(request["username"])
	if err:
		print("Username availability Check Error!")
		src.network.close(connection)

	# pack and send this response to the client
	response = { \
		"nonce": request["nonce"], \
		"response": response}

	response, err = src.crypto.asymmetrically_encrypt(src.utils.pack(response), \
		request["rolling_public_key"])
	if err:
		src.network.close(connection)

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

	except:
		print("Malformed Signup request: Dictionary key error!")
		src.network.block(connection, src.globals.HOUR)

	out, err = src.db.username_is_available(request["username"])
	if err:
		print("Username availability Check Error!")
		src.network.close(connection)

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

		out, err = src.crypto.sign(src.crypto.hash(response), request["username"])
		if err:
			print("Signature Error")
			src.network.close(connection)

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


def login(connection, request):

	"""
	STRUCTURE OF A REQUEST
	request = {
		"username": utf-8 string
		"token": bytes, SIGNED hash of the original asymmetrically encrypted message
		"nonce": bytes, replayed to the client asymmetrically
	"""

	try:
		if not (
			isinstance(request["username"], str) and \
			len(request["username"]) < src.globals.MAX_USERNAME_SIZE and \
			src.utils.username_is_vailid(request["username"])):

			print("Signature verification Error!")
			src.network.close(connection)

		if src.db.username_is_available(request["username"]):
			src.network.close(connection)

		out, err = src.crypto.verify_signature(request["username"], request["token"])
		if err:
			print("Signature verification Error!")
			src.network.close(connection)
		# skipping checking of out as checking err is enough

		"""
		response = {
				"token" = {
						"type": "sign"
						"token": bytes, signed hash of response["response"]
							}
				"response" = {
						"nonce": bytes # 1
						"replay_nonce": bytes # 2
							}
					}

		1. nonce: nonce_size bytes
			This nonce is being replayed by the server to prevent
			replay attacks and to prove to the client
			that it has the private keys
			to the public keys of what the client's
			application recognises to be the legitimate server.

		2. replay_nonce: nonce_size bytes
			This nonce is generated by the server
			and sent to the client. The client must
			replay this nonce back to the server in order
			to prove that it has the private key associated
			with the username.
		"""

		replay_nonce = src.crypto.nonce()

		response = { \
			"nonce": request["nonce"], \
			"replay_nonce": replay_nonce}

		response, err = src.crypto.asymmetrically_encrypt(src.utils.pack(response), \
			src.crypto.encryption_key(request["username"]))

		if err:
			src.network.close(connection)

		out, err = src.crypto.sign(src.crypto.hash(response), request["username"])
		if err:
			print("Signature Error")
			src.network.close(connection)

		# PLAIN HASHES HERE AND NOT SIGNED ONES
		response = src.utils.pack({ \
			"token": { \
				"type": src.globals.SIGN, \
				"token": out}, \
			"response": response})

		response = src.utils.sizeof(response) + response
		# insert timeout here!
		connection.send(response)

		print("LOGIN STEP 1 PROCESSED!")

		# now recieve data here for step two or what???
		# remember that the servers gotta crosscheck the nonce it sent too

	except:
		print("Malformed Signup request: Dictionary key error!")
		src.network.block(connection, src.globals.HOUR)



def reconnect(connection, request):
	pass


def fetch_keys(connection, request):
	pass


def update_mailbox(connection, request):
	pass


def delete_mail(connection, request):
	pass


def delete_account(connection, request):
	pass


def send_mail(connection, request):
	pass


def download_mail(connection, request):
	pass
