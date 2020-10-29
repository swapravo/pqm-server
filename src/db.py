from redis import Redis
from getpass import getpass
from sh.contrib import sudo
from sh import systemctl
from sqlite import connect


import src.globals


# using a redis instance as a sessions manager

# use a sqlite3 db as a cold store for now
# upgrade to something robust like postgresql later


def start_hot_store():

	print("Starting Redis Server!")
	#with sudo:
	#	systemctl("start", "redis-server")

	while True:
		blacklist = Redis(host="127.0.0.1", port=6379, db=0, username="blacklist", password="abc")
		try:
			if blacklist.ping():
				break
		except:
			password = getpass("Password verification for DB blacklist failed or Redis is down!")
			continue

	while True:
		print("Replace this password with an input statement")
		nonces = Redis(host="127.0.0.1", port=6379, db=1, username="nonces", password="bcd")
		try:
			if nonces.ping():
				break
		except:
			password = getpass("Password verification for DB nonces failed or Redis is down!")
			continue

	while True:
		print("Replace this password with an input statement")
		unauthenticated_clients = Redis(host="127.0.0.1", port=6379, db=2, username="unauthenticated_clients", password="cde")
		try:
			if unauthenticated_clients.ping():
				break
		except:
			password = getpass("Password verification for DB unauthenticated_clients failed or Redis is down!")
			continue

	while True:
		print("Replace this password with an input statement")
		authenticated_clients = Redis(host="127.0.0.1", port=6379, db=3, username="authenticated_clients", password="def")
		try:
			if authenticated_clients.ping():
				break
		except:
			password = getpass("Password verification for DB authenticated_clients failed or Redis is down!")
			continue

	return (blacklist, nonces, unauthenticated_clients, authenticated_clients)


def assign_buffer(client, auth):

	def _process_query(client, pipeline):
		pipeline.get(client+':requests_counter_0')
		pipeline.get(client+':requests_counter_1')
		pipeline.get(client+':requests_counter_2')
		pipeline.get(client+':requests_counter_3')
		pipeline.get(client+':requests_counter_4')
		pipeline.get(client+':buffer')
		client_data = list(map(lambda x: int(x) if x else 0, pipeline.execute()))

		if client_data[0] > src.globals.REQUEST_FILTER_0[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_0[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_0', 1)
			pipeline.expire(client+':requests_counter_0', src.globals.REQUEST_FILTER_0[1])

		if client_data[1] > src.globals.REQUEST_FILTER_1[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_1[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_1', 1)
			pipeline.expire(client+':requests_counter_1', src.globals.REQUEST_FILTER_1[1])

		if client_data[2] > src.globals.REQUEST_FILTER_2[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_2[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_2', 1)
			pipeline.expire(client+':requests_counter_2', src.globals.REQUEST_FILTER_2[1])

		if client_data[3] > src.globals.REQUEST_FILTER_3[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_3[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_3', 1)
			pipeline.expire(client+':requests_counter_3', src.globals.REQUEST_FILTER_3[1])

		if client_data[4] > src.globals.REQUEST_FILTER_4[0]:
			src.network.block(client, src.globals.REQUEST_FILTER_4[1])
			return 0
		else:
			pipeline.incrby(client+':requests_counter_4', 1)
			pipeline.expire(client+':requests_counter_4', src.globals.REQUEST_FILTER_4[1])

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
			pipeline.set(client+':buffer', src.globals.USERNAME_AVAILABILITY_CHECK_REQUEST_SIZE, ex=src.globals.STRANGER_TTL)
			pipeline.execute()
		return src.globals.USERNAME_AVAILABILITY_CHECK_REQUEST_SIZE


def start_key_db():
	db_connection = connect("./src/databases/keys/keys.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def start_mail_db():
	db_connection = connect("./src/databases/mails/mails.db")
	cursor = db_connection.cursor()
	return (db_connection, cursor)


def is_username_available(username):
	query = """SELECT * FROM USERS WHERE username = ?"""
	cursor.execute(query, (username,))
    if cursor.fetchone():
        return False
    return True


def signup_user(username, encryption_public_key, signature_public_key):
	try:
		query = """INSERT INTO USERS (username, encryption_public_key, \
			signature_public_key) VALUES (?, ?, ?)"""
		cursor.execute(query, (username, encryption_public_key, signature_public_key))
		db_connection.commit()

		# creating a new database to store the client's data in
		new_table = """CREATE TABLE MESSAGES (id INTEGER PRIMARY KEY, \
			Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, mail BLOB)"""

		user_db = connect("./src/databases/users/" + username)
		user_db_cursor = user_db.cursor()
		user_db_cursor.execute(new_table)
		user_db.commit()
		return 0

	except:
		return 1


blacklist, nonces, unauthenticated_clients, authenticated_clients = start_hot_store()
key_db_connection, key_db_cursor = start_key_db()
mail_db_connection, mail_db_cursor = start_mail_db()