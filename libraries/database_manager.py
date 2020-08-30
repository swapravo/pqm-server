# use a redis instance as a sessions manager

while True:
	print("Replace this password with an input statement")

	# contains IPs and usernames
	blacklist = Redis(host="127.0.0.1", port=6379, db=0, username="blacklist", password="abc")
	try:
		if blacklist.ping():
			break
	except:
		input("Password verification failed or Redis is down!")
		continue

while True:
	print("Replace this password with an input statement")
	nonce_tracker = Redis(host="127.0.0.1", port=6379, db=1, username="nonce_tracker", password="bcd")
	try:
		if nonce_tracker.ping():
			break
	except:
		input("Password verification failed or Redis is down!")
		continue

while True:
	print("Replace this password with an input statement")
	unauthenticated_clients = Redis(host="127.0.0.1", port=6379, db=2, username="unauthenticated_clients", password="cde")
	try:
		if unauthenticated_clients.ping():
			break
	except:
		input("Password verification failed or Redis is down!")
		continue

while True:
	print("Replace this password with an input statement")
	authenticated_clients = Redis(host="127.0.0.1", port=6379, db=3, username="authenticated_clients", password="def")
	try:
		if authenticated_clients.ping():
			break
	except:
		input("Password verification failed or Redis is down!")
		continue


# use a postgres instance as a cold store
