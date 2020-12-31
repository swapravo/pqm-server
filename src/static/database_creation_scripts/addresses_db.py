import sqlite3

db_conn = sqlite3.connect("./addresses_db")
cursor = db_conn.cursor()

# we'll be creating an empty sqlite3 db as the rest will be taken care of by
# the server

query1 = """VACUUM"""
cursor.execute(query1)
db_conn.commit()
