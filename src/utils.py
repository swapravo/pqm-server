from msgpack import packb, unpackb
from os import urandom
from time import time
from subprocess import Popen, PIPE
from string import printable
from sys import byteorder


import src.globals


def sizeof(message):
	#with 4 bytes you can represent upto 32 GiB
	return (len(message)).to_bytes(4, byteorder='little')


def pack(message):
	return packb(message, use_bin_type=True)


def unpack(message):
	try:
		return unpackb(message, raw=False)
	except:
		print("Invalid message! Unpacking message FAILED!")
		return None


def random_name_generator(length=src.globals.RANDOM_NAME_LENGTH):
	return hex(int.from_bytes(urandom(length//2), byteorder=byteorder))[2:]


def timestamp():
	# unix timestamps are 4 bytes long
	return round(time())


def execute(command, data=None):
	# SANITIZE commands here

	process = Popen([command], shell=True, stdout=PIPE, stdin=PIPE)
	if data:
		returned_data = process.communicate(input=data)
	else:
		returned_data = process.communicate()
	process.terminate()

	out, err = None, None
	if returned_data[0]:
		out = returned_data[0]
	if returned_data[1]:
		err = returned_data[1]
	return (out, err)


def username_is_vailid(username):

	# check for curse words, commands, illegal symbols
	if len(username) < 3 or len(username) > 128:
		print("Username must be atleast four and less than 129 charcters.")
		return False
	username = username.lower()
	allowed_characters = printable[:36] + '_.'
	cleaned_username = ''.join(list(filter(lambda x: x in allowed_characters, \
		username)))

	if username != cleaned_username:
		print("Illegal characters present. Allowed charcters: ", \
			' '.join(list(allowed_characters)))
		return False
	return True
