def process_username_availability_request(username):

	print("SANITIZE INPUT!")

	if username_validity_checker(username) == 1:
		# a normal client would have checked the username.
		# the user is probably forging messges.
		# BLOCK him!
		return invalid_username_code

	# save the keys in a secure DB or something
	print("BYPASSING USERNAME AVAIL CHECK")

	return username_not_found_code # OR username_foun_code


def signup(username, encryption_public_key, signature_public_key):
	print(" make sure the keys are SANITIZED!")
