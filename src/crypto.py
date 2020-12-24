from os import urandom
from hashlib import blake2b
from nacl.pwhash.argon2id import kdf
from nacl.secret import SecretBox #  xsalsa20poly1305
from nacl.utils import random as nacl_random

import src.globals
import src.utils


def nonce(size=src.globals.NONCE_SIZE):
	return urandom(size)


def encryption_key(username):
	return username + ".qmek"


def signature_key(username):
	return username + ".qmsk"


def hash(message):
	if not isinstance(message, bytes):
		print(message)
	return blake2b(message, digest_size=src.globals.HASH_SIZE).digest()


def key_is_valid(key, key_is_public=True):
	if key_is_public:
		out, err = src.utils.execute("./src/ccr -n -i --name " + \
			src.utils.random_name_generator(), key)
	else:
		out, err = src.utils.execute("./src/ccr -n -I --name " + \
			src.utils.random_name_generator(),  key)
	if err:
		return False
	elif out:
		return True
	else:
		return None


def insert_public_key(key, keyname):
	out, err = src.utils.execute("./src/ccr -y -i --name " + keyname, key)
	if err or out:
		print("Public key insertion FAILED! Codecrypt returned:", err)
	return (out, err)


def remove_public_key(keyname):
	out, err = src.utils.execute("./src/ccr -y -x " + keyname)
	if err or out:
		print("Public key removal FAILED! Codecrypt returned:", err)
	return (out, err)


def generate_encryption_keys(keyname):
	out, err = src.utils.execute("./src/ccr --gen-key ENC-256 --name " + keyname)
	if bytes("Gathering random seed bits from kernel", 'utf-8') not in err:
		print("Public key generation FAILED! Codecrypt returned:", err)
		return (out, err)
	out, err = keyname, None
	return (out, err)


def generate_signature_keys(keyname):
	out, err = src.utils.execute("./src/ccr --gen-key SIG-256 --name " + keyname)
	if bytes("Gathering random seed bits from kernel", 'utf-8') not in err:
		print("Signature key generation FAILED! Codecrypt returned:", err)
		return (out, err)
	out, err = keyname, None
	return (out, err)


def key_fingerprint(keyname):

	if keyname[-2] == 'p':
		mode = 'k'
	elif keyname[-2] == 's':
		mode = 'K'
	else:
		return (None, 1)

	out, err = src.utils.execute("./src/ccr -" + mode + " --fingerprint -F " + keyname)
	if err:
		print("Key fingerprinting FAILED!! Codecrypt returned:", err)
	else:
		out = bytes.fromhex(''.join(str(out[-81:-2], 'utf-8').split(':')))
		err = 0
	return (out, err)


def asymmetrically_encrypt(message, key):

	"""
	if public_key is an utf-8 string, infer it to be an username THAT EXISTS,
	in the db, insert it into the keyring and then encrypt with it
	else if public_key is a byte string, infer it to be a key,
	insert it into the keyring, encrypt with it and remove it after use
	"""

	out, err = None, None
	random_name = None

	if isinstance(key, str):
		out, err = insert_public_key(src.db.fetch_encryption_key(key), key)
		if err:
			return (out, 1)
	elif isinstance(key, bytes):
		random_name = src.utils.random_name_generator()
		out, err = insert_public_key(key, random_name)
		if err:
			return (out, 1)
		key = random_name
	else:
		return (out, err)

	out, err = src.utils.execute("./src/ccr -e -r " + key, message)
	if err:
		return (None, 1)

	if random_name:
		# now remove the key to keep the keyring clean
		_, err = remove_public_key(key)
		if err:
			print("Failed to remove public key", random_name)
			err = 1
	err = 0
	return (out, err)


def asymmetrically_decrypt(message, private_key_name):

	out, err = src.utils.execute("./src/ccr -d -r " + private_key_name, message)

	if not out or err:
		print("Asymmetric decryption FAILED! Codecrypt returned:")
		err = 1
	else:
		err = 0
	return (out, err)


def sign(message, recipient_name):

	out, err = src.utils.execute("./src/ccr -s -r " + recipient_name, message)

	if err:
		print("Signing FAILED! Codecrypt returned:", err)
		err = 1
	else:
		err = 0
	return (out, err)


def verify_signature(_from, signature):
	out, err = src.utils.execute("./src/ccr -v ", signature)

	# i have a bad feeling about this.
	# everytime i try to modify a signature,
	# it leads to a decryption failure
	# and not a signature verification failure
	# try forging a signature to see what it returns

	if err or not out:
		print("Signature Verification FAILED! Codecrypt returned:", err)
		out = False
		err = 1
	elif bytes(_from, 'utf-8') in out and not err:
		out = True
		err = 0

	return (out, err)


def symmetric_key_generator():
	return nacl_random(SecretBox.KEY_SIZE)


def symmetrically_encrypt(message, key):
	box = SecretBox(key)
	return box.encrypt(message, nacl_random(SecretBox.NONCE_SIZE))


def symmetrically_decrypt(message, key):
	try:
		box = SecretBox(key)
		return box.decrypt(message)
	except:
		print("Symmetric decryption FAILED!")
		return None
