'''
def ip(connection):
	#print("IP: ", connection.getsockname())
	return connection.getsockname()[0]

def assign_buffer2(ip_address):

	"""
	This fn allows an attacker on the same network as a normal user (with the
	same public IP) access to a buffer that was assigned for the normal user!
	He can also get the normal user blocked by DoSing our server! Find a way
	to uniquely identify differnt users on the sawe network!
	"""


	data = authenticated_clients.hgetall(ip_address)

	"""
	rolling_ID
	{0: rolling_authenticated_token, 1: symmetric_session_key, 2: username,
	3: IP, 4: buffer_allocated 5: requests made in the last second,
	6: requests made in the last minute, 7: requests made in the last hour,
	9: requests made in the last day, 10: emails sent in the last hour,
	11: emails sent in the last day}
	"""

	if data:

		# do stuff

	else:
		data = unauthenticated_clients.hgetall(ip_address)

		"""
		IP address
		{0: requests made in the last second, 1: requests in the last minute
		2: requests made in the last hour 3: requests made in the last day,
		4: buffer_size}
		"""

		if data:
			if int(data[b'0']) > max_requests_per_second:
				block(ip_address, block_second) # or the username???
				# reset the counter
				return 0
			else:
				#increase this counter by 1

			if int(data[b'1']) > max_requests_per_minute:
				block(ip_address, block_minute)
				# reset the count
				return 0
			else:
				# increase the counter

			if int(data[b'2']) > max_requests_per_hour:
				block(ip_address, block_hour)
				#reset the counter
				return 0
			else:
				# increase the counter

def recieve2(connection, data_size)

	if not data_size:
		connection.shutdown(RDWR)
		connection.close()
		return b''

	fragments = []

	while True:
		chunk = connection.recv(data_size)

		if not chunk: break
		fragments.append(chunk)

	return b''.join(fragments)
'''


def close(connection):
	connection.shutdown(SHUT_RDWR)
	connection.close()

def block(whom, time):
	print("Blocking", whom, "for", time, "seconds!")
	blacklist.set(whom, 0, ex=time)
	close(connection)


def assign_buffer(client, auth):

	def _process_query(client, pipeline):
		pipeline.get(client+':requests_counter_0')
		pipeline.get(client+':requests_counter_1')
		pipeline.get(client+':requests_counter_2')
		pipeline.get(client+':requests_counter_3')
		pipeline.get(client+':requests_counter_4')
		pipeline.get(client+':buffer')
		client_data = list(map(lambda x: int(x) if x else 0, pipeline.execute()))

		if client_data[0] > request_filter_0[0]:
			block(client, request_filter_0[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_0', 1)
			pipeline.expire(client+':requests_counter_0', request_filter_0[1])

		if client_data[1] > request_filter_1[0]:
			block(client, request_filter_1[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_1', 1)
			pipeline.expire(client+':requests_counter_1', request_filter_1[1])

		if client_data[2] > request_filter_2[0]:
			block(client, request_filter_2[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_2', 1)
			pipeline.expire(client+':requests_counter_2', request_filter_2[1])

		if client_data[3] > request_filter_3[0]:
			block(client, request_filter_3[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_3', 1)
			pipeline.expire(client+':requests_counter_3', request_filter_3[1])

		if client_data[4] > request_filter_4[0]:
			block(client, request_filter_4[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_4', 1)
			pipeline.expire(client+':requests_counter_4', request_filter_4[1])

		if all(pipeline.execute()):
			return client_data[5]
		return 0

	if auth: # auth is true if the ip+port is in the list authenticated_clients
		with authenticated_clients.pipeline() as pipeline:
			return _process_query(client, pipeline)

	elif unauthenticated_clients.exists(client):
		with unauthenticated_clients.pipeline() as pipeline:
			return _process_query(client, pipeline)
	else:
		with unauthenticated_clients.pipeline() as pipeline:
			pipeline.set(client, 0, ex=stranger_ttl)
			pipeline.set(client+':buffer', username_availability_check_request_size, ex=stranger_ttl)
			pipeline.execute()
		return username_availability_check_request_size

def recieve(connection, max_payload_size):

	if max_payload_size == 0:
		return b''

	payload_size = int.from_bytes(connection.recv(4), byteorder='little')
	if payload_size > max_payload_size:
		close(connection)
		return b''

	data = bytearray(payload_size)
	pos = 0
	#print("payload_size: ", payload_size)
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


def handler(connection, auth):

	basicConfig(level=DEBUG)
	#logger = getLogger("process-%r" % (address,))
	hash = signature = None
	ip, port = connection.getsockname()
	port = str(port)

	try:
		while True:
			#debug("\tConnected to %r at %r", connection)

			version = connection.recv(2)
			#print("version:", version)
			# do version specific stuff after this

			data = memoryview(recieve(connection, assign_buffer(ip + ':' + port, auth)))
			#from hashlib import md5
			#print(md5(data).hexdigest())
			#print("recived from the client: ", data.tobytes())
			# print("length of data: ",  data.nbytes)
			# print(assign_buffer(ip(connection)))

			# close the socket if the client sends nothing
			if not data:
				debug("Socket closed remotely!")
				close(connection)
				return

			# if the message has a hash, verify it now
			# elif its a signature note it down
			if bytes([data[0]]) == hash_denoter:
				recieved_hash = data[1:1+hash_size].tobytes()
				hash_ = _hash(data[1+hash_size:])
				if recieved_hash != hash_:
					print("Hash verification failed!!")
					close(connection)
					return
				else:
					del hash_, recieved_hash
					data = data[1+hash_size:]
			elif bytes([data[0]]) == signature_denoter:
				#print("sig den")
				signature_size = int.from_bytes(data[1:3], byteorder='little')
				signature = data[3:3+signature_size]
				data = data[3+signature_size:]
			else:
				#print("garbage!", data[0])
				continue

			plaintext = asymmetrically_decrypt(data, encryption_key(server))
			del data

			if plaintext == 1:
				print("Decryption FAILED!")
				continue

			plaintext = unpack(plaintext, raw=False)

			if timedelta(timestamp(), plaintext["timestamp"]) > max_allowable_time_delta:
				print("TLE DETECTED!")
				continue

			del plaintext["timestamp"]

			recieved_nonce = plaintext["nonce"]
			if nonce_tracker.exists(recieved_nonce):
				# there is something fishy.
				# block this user for a few minutes
				print("Nonce collision Detected!")
				# Or should i block this IP instead?
				block(ip+':'+port, max_allowable_time_delta)
				return

			nonce_tracker.set(recieved_nonce, 0, ex=max_allowable_time_delta)

			# check user request and outsource it to the necessary function
			recieved_request = plaintext["request_code"]

			if recieved_request == username_availability_check_code:

				username = plaintext["username"]

				rolling_public_key = plaintext["rolling_public_key"]

				response_code = process_username_availability_request(username)

				if response_code == invalid_username_code:
					# This will happen only if the client sends a message
					# with illegal characters
					# determine a method for dynamically increasing the duration
					block(ip, stranger_ttl)
					return

				elif response_code == username_not_found_code:
					# increase the size of the buffer alloted to him
					unauthenticated_clients.set(ip+':'+port+':buffer', signup_request_size)

				# pack and send this response to the client
				message = {"recieved_request": plaintext["request_code"], \
				"nonce": plaintext["nonce"], "response_code": response_code}

				# print("Message: " , message)
				random_name = random_name_generator()

				# ASSUMING ROLLING_PUBLIC_KEY HAS BEEN SANITIZED
				# need to add this temporary key in order to encrypt messages with it
				# use a RAMDISK for THIS
				with open(user_home+ccr_folder+random_name, 'wb') as fo:
					fo.write(rolling_public_key)

				execute("./libraries/ccr -i -R " + user_home+ccr_folder+random_name + " --name " + random_name)
				#print("ran name: ", random_name)
				ciphertext = asymmetrically_encrypt(pack(message, use_bin_type=True), random_name)
				#print("Ciphertext: ", ciphertext)
				remove(user_home+ccr_folder+random_name)
				ciphertext = _hash(ciphertext) + ciphertext

				response = (len(ciphertext)).to_bytes(4, byteorder='little') + ciphertext
				connection.sendall(response)
				print("REQUEST PROCESSED SUCCESSFULLY!")
				continue

			elif recieved_request == signup_code:
				print("IN SIGNUP")
				username = plaintext[timestamp_size+request_size:timestamp_size+request_size+max_username_size].tobytes().lstrip(b'\x00')

				encryption_public_key_size = int.from_bytes(plaintext[timestamp_size+request_size+max_username_size: \
								timestamp_size+request_size+max_username_size+max_encryption_public_key_size], byteorder='little')

				encryption_public_key = plaintext[timestamp_size+request_size+max_username_size+max_encryption_public_key_size: \
								timestamp_size+request_size+max_username_size+max_encryption_public_key_size+encryption_public_key_size]

				signature_public_key_size = int.from_bytes(plaintext[timestamp_size+request_size+max_username_size+max_encryption_public_key_size+ \
								encryption_public_key_size: timestamp_size+request_size+max_username_size+max_encryption_public_key_size+ \
								encryption_public_key_size+max_signature_public_key_size], byteorder='little')

				signature_public_key =  plaintext[timestamp_size+request_size+max_username_size+max_encryption_public_key_size+\
								encryption_public_key_size+max_signature_public_key_size: \
								timestamp_size+request_size+max_username_size+max_encryption_public_key_size+ \
								encryption_public_key_size+max_signature_public_key_size+signature_public_key_size]

				process_signup_request(username, encryption_public_key, signature_public_key)


	except:
		exception("Problem handling request")

	finally:
		debug("Closing socket")
		connection.close()
