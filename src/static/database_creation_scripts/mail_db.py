import sqlite3

db_conn = sqlite3.connect("./mail_db")
cursor = db_conn.cursor()


query = """
	CREATE TABLE mails (
		id BLOB PRIMARY KEY,
		mail BLOB NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
		score INT NOT NULL
		)
	"""

cursor.execute(query)

db_conn.commit()
