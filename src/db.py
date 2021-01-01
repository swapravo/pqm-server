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
import src.crypto


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
	db_connection = connect("./src/databases/key.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def start_mail_db():
	db_connection = connect("./src/databases/mail.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def start_address_db():
	db_connection = connect("./src/databases/addresses.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def username_is_available(_username):

	try:
		query = """
			SELECT username FROM keys
			WHERE username=?
			"""
		key_db_cursor.execute(query, (_username,))

		if key_db_cursor.fetchone():
			return (False, 0)
		return (True, 0)

	except Exception as e:
		print("Database Error:", e)
		return (None, 1)


def add_user(_username, encryption_public_key, signature_public_key):

	try:
		query = """
			INSERT INTO keys
				(username,
				encryption_public_key,
				signature_public_key)
			VALUES (?, ?, ?)
			"""
		key_db_cursor.execute(query, (_username, encryption_public_key, \
			signature_public_key))
		user_primary_key_query = """SELECT last_insert_rowid()"""
		key_db_cursor.execute(user_primary_key_query)
		user_primary_key = key_db_cursor.fetchone()[0]

		if not isinstance(user_primary_key, int):
			return (None, 1)
		key_db_connection.commit()

		# is it still unsafe?
		# creating a new database to store the client's data in
		# sqlite3 does not allow table names to begin with numbers
		new_address_table_query = """CREATE TABLE id_""" + \
			str(user_primary_key) + """
				(hash BLOB PRIMARY KEY,
				from_username TEXT NOT NULL,
				to_username TEXT NOT NULL)"""

		address_db_cursor.execute(new_address_table_query)
		address_db_connection.commit()

	except Exception as e:
		print("Database Error:", e)
		return (None, 1)
	return (None, 0)


def fetch_keys(_username):

	try:
		query = """
			SELECT encryption_public_key, signature_public_key
			FROM keys
			WHERE username=?
			"""
		key_db_cursor.execute(query, (_username,))

		out = key_db_cursor.fetchone()
		if out:
			return (out, 0)
		return (None, 0)
	except:
		return (None, 1)


def last_login_timestamp(_username):

	try:
		query = """
			SELECT last_login_timestamp
			FROM keys
			WHERE username=?
			"""
		key_db_cursor.execute(query, (_username,))

		out = key_db_cursor.fetchone()
		if out:
			return (out[0], 0)
		return (None, 0)
	except:
		return (None, 1)


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


def delete_mail(_from, _hash):

	# STILL UNSAFE?
	delete_metadata = """DELETE FROM id_""" + \
		str(user_id(_from)) + """ WHERE id=?"""

	retrieve_score = """
		SELECT score
		FROM mails
		WHERE id=?
		"""

	decrease_score = """
		UPDATE mails
		SET score=?
		WHERE id=?
		"""

	delete_mail = """
		DELETE FROM mails
		WHERE id=?
		"""

	try:
		address_db_cursor.execute(delete_metadata)
		address_db_connection.commit()

		mail_db_cursor.execute(retrieve_score, (_hash,))
		score = mail_db_cursor.fetchone()
		if score is None:
			return (None, 1)
		score = int(score[0])
		# as every mail is custom-encrypted for the recipient, the max score can be 2
		if score == 2:
			mail_db_cursor.execute(decrease_score, (score-1, _hash,))
		elif score == 1:
			mail_db_cursor.execute(delete_mail, (_hash,))
		else:
			return (None, 1)
		mail_db_connection.commit()
		return (None, 0)
	except Exception as e:
		print("Database Error:", e)
		return (None, 1)


def delete_account():
	pass


def user_id(username):
	query = """
		SELECT id
		FROM keys
		WHERE username=?
		"""
	key_db_cursor.execute(query, (username,))
	uid = key_db_cursor.fetchone()
	if uid is None:
		return 0
	return int(uid[0])


def add_mail(_from, to, email):

	from_uid = user_id(_from)
	if not from_uid:
		return (None, 1)

	to_uid = user_id(to)
	if not to_uid:
		return (None, 1)

	# still unsafe?
	# check whether the timestamp is being added or not
	address_query1 = """INSERT INTO id_""" + str(to_uid) + """ (
		from_username,
		to_username,
		hash)
		VALUES (?, ?, ?)
		"""

	address_query2 = """INSERT INTO id_""" + str(from_uid) + """ (
		from_username,
		to_username,
		hash)
		VALUES (?, ?, ?)
		"""

	mail_query = """
		INSERT INTO mails (
		id,
		mail,
		score)
		VALUES (?, ?, ?)
		"""

	_hash = src.crypto.hash(email)

	try:
		address_db_cursor.execute(address_query1, (_from, to, _hash,))
		address_db_cursor.execute(address_query2, (_from, to, _hash,))
		address_db_connection.commit()
		mail_db_cursor.execute(mail_query, (_hash, email, 2,))
		mail_db_connection.commit()
		return (None, 0)
	except Exception as e:
		print("Database Error:", e)
		return (None, 1)


blacklist, nonces, unauthenticated_clients, authenticated_clients = start_hot_store()
key_db_connection, key_db_cursor = start_key_db()
address_db_connection, address_db_cursor = start_address_db()
mail_db_connection, mail_db_cursor = start_mail_db()
