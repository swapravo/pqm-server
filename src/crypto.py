from os import urandom, remove
from os.path import isfile
from sys import byteorder
from hashlib import blake2b
from nacl.pwhash.argon2id import kdf
from nacl.secret import SecretBox #xsalsa20poly1305
from nacl.utils import random as nacl_random


import src.globals
import src.utils


def nonce(size=src.globals.NONCE_SIZE):
	return urandom(size)


def insert_public_key(key, keyname):
	out, err = src.utils.execute("./src/ccr -y -i --name " + keyname, key)
	if err or out:
		print("Public key insertion FAILED!")
		print(out, err)
		return 1
	return 0


def encryption_key(username):
	return username + ".qmek"


def signature_key(username):
	return username + ".qmsk"


def hash(message):
	return blake2b(message, digest_size=src.globals.HASH_SIZE).digest()


# # BUG: NOT TESTED
def validate_key(key):
	# for public keys
	out, err = src.util.execute("./src/ccr -n -y -i " + src.utils.random_name_generator(), key)
	# for private keys
	out, err = src.util.execute("./src/ccr -n -y -I " + src.utils.random_name_generator(), key)


def insert_public_key(key, keyname):
	out, err =src.utils.execute("./src/ccr -y -i --name " + keyname, key)
	if err or out:
		return 1
	return 0


def remove_public_key(keyname):
	out, err =src.utils.execute("./src/ccr -y -x " + keyname)
	if err or out:
		return 1
	return 0


def generate_encryption_keys(keyname):
	print("Generating asymmetric encryption keys.")
	print("THESE FILES NEED TO BE (f)LOCKED!!!")
	out, err = src.utils.execute("./src/ccr --gen-key ENC-256 --name " + keyname)
	if not bytes("Gathering random seed bits from kernel", 'utf-8') in err:
		print(err)
		return 1
	return keyname


def generate_signature_keys(keyname):
	print("Generating signing Keys. This is going to take a while.")
	print("THESE FILES NEED TO BE (f)LOCKED!!!")
	out, err = src.utils.execute("./src/ccr --gen-key SIG-256 --name " + keyname)
	if not bytes("Gathering random seed bits from kernel", 'utf-8') in err:
		print(err)
		return 1
	return keyname


def key_fingerprint(keyname):

	if keyname[-2] == 'p':
		mode = 'k'
	elif keyname[-2] == 's':
		mode = 'K'
	else:
		return 1

	out, err = src.utils.execute("./src/ccr -" + mode + " --fingerprint -F " + keyname)
	if err: return 1
	return bytes.fromhex(''.join(str(out[-81:-2], 'utf-8').split(':')))


def asymmetrically_encrypt(message, key):

	"""
	if public_key is an utf-8 string, infer it to be an username THAT EXISTS,
	in the db, insert it into the keyring and then encrypt with it
	else if public_key is a byte string, infer it to be a key,
	insert it into the keyring, encrypt with it and remove it after use
	"""

	random_name = None

	if instanceof(key, str):
		insert_public_key(src.db.fetch_encryption_key(key), key)
	elif instanceof(public_key, bytes):
		random_name = src.utils.random_name_generator()
		insert_public_key(key, random_name)
		key = random_name
	else:
		return 1

	out, err = src.utils.execute("./src/ccr -e -r " + key, message)

	if random_name:
		# now remove the key to keep the keyring clean
		_out, _err = remove_public_key(key)
		out |= _out
		err |= _err

	if err: return 1
	return out


def asymmetrically_decrypt(message, private_key_name):

	out, err = src.utils.execute("./src/ccr -d -r " + private_key_name, message)

	if err: return 1
	return out


def sign(message, recipient_name):

	out, err = src.utils.execute("./src/ccr -s -r " + recipient_name, message)

	if err: return 1
	return out


def verify_signature(signature):
	out, err = src.utils.execute("./src/ccr -v ", signature)

	# i have a bad feeling about this.
	# everytime i try to modify a signature,
	# it leads to a decryption failure
	# and not a signature verification failure
	# try forging a signature to see what it returns

	if err or not out: return 1
	return 0


def symmetrically_encrypt(message, key):
	box = SecretBox(key)
	return box.encrypt(message, nacl_random(SecretBox.NONCE_SIZE))


def symmetrically_decrypt(message, key):
	box = SecretBox(key)
	try:
		return box.decrypt(message)
	except:
		return 1


def asymmetrically_respond(connection, message, key, key_name):

	# ASSUMING ROLLING_PUBLIC_KEY HAS BEEN SANITIZED
	# need to add this temporary key in order to encrypt messages with it
	# use a RAMDISK for THIS
	with open(src.globals.USER_HOME+src.globals.CCR_FOLDER+key_name, 'wb') as fo:
		fo.write(key)

	#make sure these get executed
	# include the try catches
	src.utils.execute("./src/ccr -i -R " + src.globals.USER_HOME + src.globals.CCR_FOLDER + key_name + " --name " + key_name)
	ciphertext = asymmetrically_encrypt(src.utils.pack(message), key_name)
	remove(src.globals.USER_HOME+src.globals.CCR_FOLDER+key_name)

	ciphertext = hash(ciphertext) + ciphertext
	response = (len(ciphertext)).to_bytes(4, byteorder='little') + ciphertext

	# insert timeout here!
	connection.sendall(response)
