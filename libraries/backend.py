def random_name_generator(length=random_name_length):
	return hex(int.from_bytes(urandom(length//2), byteorder=byteorder))[2:]


def timestamp():
	# sync server with NTP
	# unix timestamps are 4 bytes long
	return round(time()).to_bytes(4, byteorder='little')


def timedelta(timestamp1, timestamp2):
	delta = int.from_bytes(timestamp1, byteorder='little') - int.from_bytes(timestamp2, byteorder='little')
	if delta < 0:
		return -delta
	return delta


def encryption_key(username):
	return username + ".qmek"


def signature_key(username):
	return username + ".qmsk"


def _hash(message):
	return blake2b(message, digest_size=hash_size).digest()


def execute(command):

	process = Popen([command], shell=True, stdout=PIPE, stderr=PIPE) #  returns (OUT, ERR)
	returned_data = process.communicate()
	process.terminate()
	out = err = 0
	if returned_data[0] == b'' or returned_data[0] == None:
		out = 0
	else:
		out = returned_data[0]
	if returned_data[1] == b'' or returned_data[1] == None:
		err = 0
	else:
		err = returned_data[1]
	return (out, err)



def key_fingerprint(keyname):

	if keyname[-2] == 'p':
		mode = 'k'
	elif keyname[-2] == 's':
		mode = 'K'
	else:
		return 1

	out, err = execute("./libraries/ccr -" + mode + " --fingerprint -F " + keyname)

	if err: return 1

	return bytes.fromhex(''.join(str(out[-81:-2], 'utf-8').split(':')))


def asymmetrically_encrypt(message, public_key_name):

	process = Popen(["./libraries/ccr -e -r " + public_key_name], shell=True, stdout=PIPE, stdin=PIPE)
	returned_data = process.communicate(input=message)
	process.terminate()

	#codecrypt returns a None if the encryption is successful
	assert returned_data[1] == None

	return returned_data[0]


def asymmetrically_decrypt(message, private_key_name):

	#handle decryption failures => wrong/missing private key
	process = Popen(["./libraries/ccr -d -r " + private_key_name], shell=True, stdout=PIPE, stdin=PIPE)
	returned_data = process.communicate(input=message)
	process.terminate()

	if returned_data[0] == b'':
		return 1
	return returned_data[0]


def username_validity_checker(username):

	# check for curse words, commands, illegal symbols
	if len(username) < 3 or len(username) > 128:
		print("Username must be atleast four and less than 129 charcters.")
		return 1

	username = username.lower()
	allowed_characters = printable[:36] + '_.'
	cleaned_username = ''.join(list(filter(lambda x: x in allowed_characters, username)))

	if username != cleaned_username:
		print("Illegal characters present. Allowed charcters: ", ' '.join(list(allowed_characters)))
		return 1

	return 0
