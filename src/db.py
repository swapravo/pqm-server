"""
PLEASE REMEMBER THAT THE FUNCTIONS HERE TRUST THE DATA THAT IS
PROVIDED TO THEM. THEREFORE, DATA MUST BE VALIDATED BEFORE SENDING
IT OVER TO HERE. TRY NOT FEEDING FUNCTIONS CONNECTION OBJECTS
"""

from redis import Redis
from getpass import getpass
from sh.contrib import sudo
from sh import systemctl
from sqlite3 import connect

import src.globals


def start_hot_store():

	print("Starting Redis Server!")
	#with sudo:
	#	systemctl("start", "redis-server")

	while True:
		_blacklist = Redis(host="127.0.0.1", port=6379, db=0, \
			username="blacklist", password="abc")
		try:
			if _blacklist.ping():
				break
		except:
			password = getpass("Password verification for DB blacklist failed \
				or Redis is down!")
			continue

	while True:
		print("Replace this password with an input statement")
		_nonces = Redis(host="127.0.0.1", port=6379, db=1, username="nonces", \
			password="bcd")
		try:
			if _nonces.ping():
				break
		except:
			password = getpass("Password verification for DB nonces failed or \
				Redis is down!")
			continue

	while True:
		print("Replace this password with an input statement")
		_unauthenticated_clients = Redis(host="127.0.0.1", port=6379, db=2, \
			username="unauthenticated_clients", password="cde")
		try:
			if _unauthenticated_clients.ping():
				break
		except:
			password = getpass("Password verification for DB \
				unauthenticated_clients failed or Redis is down!")
			continue

	while True:
		print("Replace this password with an input statement")
		_authenticated_clients = Redis(host="127.0.0.1", port=6379, db=3, \
			username="authenticated_clients", password="def")
		try:
			if _authenticated_clients.ping():
				break
		except:
			password = getpass("Password verification for DB \
				authenticated_clients failed or Redis is down!")
			continue

	return (_blacklist, _nonces, _unauthenticated_clients, _authenticated_clients)


def assign_buffer(client, auth):

	def _process_query(client, pipeline):
		pipeline.get(client+':requests_counter_0')
		pipeline.get(client+':requests_counter_1')
		pipeline.get(client+':requests_counter_2')
		pipeline.get(client+':requests_counter_3')
		pipeline.get(client+':requests_counter_4')
		pipeline.get(client+':buffer')
		client_data = list(map(lambda x: int(x) if x else 0, \
			pipeline.execute()))

		if client_data[0] > src.globals.REQUEST_FILTER_0[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_0[1])
			return 0

		pipeline.incrby(client+':requests_counter_0', 1)
		pipeline.expire(client+':requests_counter_0', \
			src.globals.REQUEST_FILTER_0[1])

		if client_data[1] > src.globals.REQUEST_FILTER_1[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_1[1])
			return 0

		pipeline.incrby(client+':requests_counter_1', 1)
		pipeline.expire(client+':requests_counter_1', \
			src.globals.REQUEST_FILTER_1[1])

		if client_data[2] > src.globals.REQUEST_FILTER_2[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_2[1])
			return 0

		pipeline.incrby(client+':requests_counter_2', 1)
		pipeline.expire(client+':requests_counter_2', \
			src.globals.REQUEST_FILTER_2[1])

		if client_data[3] > src.globals.REQUEST_FILTER_3[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_3[1])
			return 0

		pipeline.incrby(client+':requests_counter_3', 1)
		pipeline.expire(client+':requests_counter_3', \
			src.globals.REQUEST_FILTER_3[1])

		if client_data[4] > src.globals.REQUEST_FILTER_4[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_4[1])
			return 0

		pipeline.incrby(client+':requests_counter_4', 1)
		pipeline.expire(client+':requests_counter_4', \
			src.globals.REQUEST_FILTER_4[1])

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
			pipeline.set(client, 0, ex=src.globals.STRANGER_TTL)
			pipeline.set(client+':buffer', \
				src.globals.USERNAME_AVAILABILITY_CHECK_REQUEST_SIZE, \
				ex=src.globals.STRANGER_TTL)
			pipeline.execute()
		return src.globals.USERNAME_AVAILABILITY_CHECK_REQUEST_SIZE


def username(connection):
	"""
	this function takes a connection object and returns the username
	of the person connected
	"""
	pass


def start_key_db():
	db_connection = connect("./src/databases/keys/keys.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def start_mail_db():
	db_connection = connect("./src/databases/mails/mails.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def username_is_available(_username):

	out, err = None, None
	try:
		query = """
			SELECT * FROM USERS
			WHERE username=?
			"""
		key_db_cursor.execute(query, (_username,))

		if key_db_cursor.fetchone():
			# see what it returns
			out = src.globals.USERNAME_FOUND
		else:
			out = src.globals.USERNAME_NOT_FOUND
		err = 0

	except Error as e:
		print("Database Error:", e)
		err = 1

	err = 0
	return (out, err)


def add_user(_username, encryption_public_key, signature_public_key):

	out, err = None, None

	try:
		query = """
			INSERT INTO USERS
				(username,
				encryption_public_key,
				signature_public_key)
			VALUES (?, ?, ?)
			"""
		key_db_cursor.execute(query, (_username, encryption_public_key, \
			signature_public_key))
		key_db_connection.commit()

		# creating a new database to store the client's data in
		new_table = """
			CREATE TABLE MESSAGES
				(id INTEGER PRIMARY KEY,
				Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				mail BLOB)
			"""
		user_db = connect("./src/databases/users/" + _username)
		user_db_cursor = user_db.cursor()
		user_db_cursor.execute(new_table)
		user_db.commit()

	except:
		err = 1
		return (out, err)
	err = 0
	return (out, err)


def fetch_keys(_username):

	out, err = None, None
	try:
		query = """
			SELECT * FROM USERS
			WHERE username=?
			"""
		key_db_cursor.execute(query, (_username,))

		out = key_db_cursor.fetchone()
		print("This is supposed to be a byte string:", out)
		if not out:
			out = src.globals.USERNAME_NOT_FOUND

	except Error as e:
		print("Database Error:", e)
		err = 1

	err = 0
	return (out, err)


def last_login_timestamp(_username):
	"""
	returns the last login unix
	timestamp of the user
	"""
	return


def update_mailbox(_username):
	"""
	set a limit of how much data can
	be fetched at once
	"""
	timestamp = src.db.last_login_timestamp(username)
	# fetch mails that were added to the users sync_mailbox
	# after this timestamp
	# dont serialise it here
	# if there are no new mails, return None
	return


def delete_mail():
	pass


def delete_account():
	pass


def add_mail(_from, to, email):
	return


blacklist, nonces, unauthenticated_clients, authenticated_clients = start_hot_store()
key_db_connection, key_db_cursor = start_key_db()
mail_db_connection, mail_db_cursor = start_mail_db()
