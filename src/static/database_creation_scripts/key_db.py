import sqlite3

db_conn = sqlite3.connect("./key_db")
cursor = db_conn.cursor()


query = """
	CREATE TABLE keys (
		id INTEGER PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		encryption_public_key BLOB UNIQUE NOT NULL,
		signature_public_key BLOB UNIQUE NOT NULL
		)
	"""

cursor.execute(query)

db_conn.commit()
