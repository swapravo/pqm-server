from os import urandom
from time import time
from subprocess import Popen, PIPE
from string import printable
from sys import byteorder


import src.globals


def random_name_generator(length=src.globals.RANDOM_NAME_LENGTH):
	return hex(int.from_bytes(urandom(length//2), byteorder=byteorder))[2:]


def timestamp():
	# unix timestamps are 4 bytes long
	return round(time()).to_bytes(4, byteorder='little')


def timedelta(timestamp1, timestamp2):
	delta = int.from_bytes(timestamp1, byteorder='little') - int.from_bytes(timestamp2, byteorder='little')
	if delta < 0:
		return -delta
	return delta


def execute(command, data=None):
    # SANITIZE command

	if data:
		process = Popen([command], shell=True, stdout=PIPE, stdin=PIPE)
		returned_data = process.communicate(input=data)
	else:
		process = Popen([command], shell=True, stdout=PIPE, stderr=PIPE)
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


def username_validity_checker(username):

	username = str(username, 'utf-8').lower()
	# check for cuss words, commands, illegal symbols
	if len(username) < 4 or len(username) > src.globals.MAX_USERNAME_SIZE:
		return 1

	allowed_characters = printable[:36] + '_.'

	if username != "".join(map(lambda x: x if x in allowed_characters else '', username)):
		return 1
	return 0