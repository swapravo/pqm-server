from walrus import Database
from socket import SHUT_RDWR
from os import urandom, remove
from sys import byteorder
from logging import basicConfig, info, exception, DEBUG, debug, getLogger
from time import time
from subprocess import Popen, PIPE
#from threading import Timer
from hashlib import sha512, blake2b
from string import printable
from pathlib import Path


# global variables

shutdown = ""

asymmetric_byte = b'\xaa' #10101010

symmetric_byte = b'U'     #01010101

header_byte_size = 1

server = "server"

server_ip = "127.0.0.1"

server_port = 9000

user_home = str(Path.home())+'/'

ccr_folder = ".ccr/"

version = "0.1"

random_name_length = 16 # characters in hex

nonce_size = 32

hash_size = 32

# UNIX timestamps
timestamp_size = 4

max_username_size = 64

message_id_size = 2

request_size = 2

response_size = 2

rolling_id_size = 8

rolling_authentication_token_size = 32

max_encryption_public_key_size = 2

max_signature_public_key_size = 2

# rolling_public_key_size = max_encryption_public_key_size + random_name_length

key_fingerprint_size = 64

max_address_list_size = 2

bcc_address_list_size = 1

cc_address_list_size = 1

username_availability_check_request_size = 1024 * 13 # THIS NEEDS TO BE TRIMMED # 1 + nonce_size + max_username_size + request_size + rolling_public_key_size + hash_size

username_availability_check_response_size = 1024 * 16 # THIS NEEDS TO BE TRIMMED

signup_request_size = header_byte_size + nonce_size + max_username_size + request_size + max_encryption_public_key_size + max_signature_public_key_size

signup_response_size = 1024 * 16 # THIS NEEDS TO BE TRIMMED

# buffer sizes according to the 'state' of the client
# (DMZ, signing_up,  logging_in, logged_in, sending_mail)
buffer_sizes = (1024 ** 1 * 16, 1024 ** 1 * 20, 1024 ** 1 * 32, 1024 ** 1 * 32, 1024 ** 2 * 8) # THESE VALUES NEED TO BE TRIMMED

# CHANGE THESE VALUES ACCORDING TO THE PLAN OF THE CLIENT

max_requests_per_second = 2

block_second = 5

max_requests_per_minute = 20

block_minute = 60

max_requests_per_hour = 250

block_hour = 60*60

max_requests_per_day = 1000

block_day = 60*60*24

max_emails_per_minute = 3

max_emails_per_hour = 20

max_emails_pet_day = 100

max_allowable_time_delta = 60 # seconds


def code(n):
	return (n).to_bytes(2, byteorder='little')


print("THESE CODES ARE TEMPORARY!!!")


not_found_code = code(1)

forbidden_code = code(2)

failure_code = code(3)

decryption_failure_code = code(4)

login_step_1_code = code(5)

login_step_2_code = code(6)

time_limit_exceeded_code = code(7)

username_not_found_code = code(8)

username_found_code = code(9)

nonce_verification_failed_code = code(10)

email_upcoming_code = code(11)

is_an_email_code = code(12)

update_mailbox_code = code(13)

delete_message_code = code(14)

shred_mailbox_code = code(15)

close_account_code = code(16)

close_account_successful_code = code(17)

close_account_failed = code(18)

logout_code = code(19)

logout_successful_code = code(20)

logout_failed_code = code(21)

download_public_keys = code(22)

fetch_public_keys_code = code(23)

signup_code = code(24)

username_availability_check_code = code(25)

no_changes_in_mailbox = code(26)

invalid_username_code = code(27)


print("\nLoading modules...\n")


with open("./libraries/backend.py") as backend_module:
	cmd  = backend_module.read()
exec(cmd)
del backend_module
print("Backend loaded...")


with open("./libraries/database_manager.py") as database_manager_module:
	cmd = database_manager_module.read()
exec(cmd)
del database_manager_module
print("Databases loaded...")


with open("./libraries/request_processor.py") as request_processor_module:
	cmd = request_processor_module.read()
exec(cmd)
del request_processor_module
print("Request processor loaded...")


with open("./libraries/network_manager.py") as network_manager_module:
	cmd = network_manager_module.read()
exec(cmd)
del network_manager_module
print("Network manager loaded...")


#with open("./libraries/scheduler.py") as scheduler_module:
#	cmd = scheduler_module.read()
#exec(cmd)
#del scheduler_module
#print("Scheduler loaded...")


with open("./libraries/shutdown.py") as shutdown_module:
	shutdown = compile(shutdown_module.read(), '<string>', 'exec')
del shutdown_module
# exec it when shutting server the down

print("Loading server...")
with open("./libraries/server.py") as server_module:
	cmd = server_module.read()
exec(cmd)

