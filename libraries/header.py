from redis import Redis
from socket import SHUT_RDWR
from os import urandom, remove
from sys import byteorder
from msgpack import packb as pack, unpackb as unpack
from logging import basicConfig, info, exception, DEBUG, debug, getLogger
from time import time
from subprocess import Popen, PIPE
from hashlib import sha512, blake2b
from string import printable
from pathlib import Path


# global variables

shutdown = ""

signature_denoter = b'\x00' #10101010

hash_denoter = b'\xff'     #01010101

server = "server"

server_ip = "127.0.0.1"

server_port = 9000

user_home = str(Path.home())+'/'

ccr_folder = ".ccr/"

random_name_length = 16 # characters in hex

nonce_size = 32

hash_size = 32

# UNIX timestamps
timestamp_size = 4

max_username_size = 64

message_id_size = 2

request_code_size = 2

response_code_size = 2

rolling_id_size = 8

rolling_authentication_token_size = 32

key_fingerprint_size = 64

max_address_list_size = 100

username_availability_check_request_size = 1024 * 16 # THIS NEEDS TO BE TRIMMED
signup_request_size = 1024 ** 1 * 32
login_request_size = 1024 ** 1 * 32

false_signature_block_time = 60 * 60
stranger_ttl = 10 * 60

request_filter_0 = (4, 10)
request_filter_1 = (20, 60)
request_filter_2 = (200, 60*15)
request_filter_3 = (400, 60*60)
request_filter_4 = (2000, 60*60*12)


# to be fetched from the database of clients!
max_emails_per_hour = 20
max_emails_per_day = 100

max_allowable_time_delta = 90 # seconds


def code(n):
	return (n).to_bytes(2, byteorder='little')


print("THESE CODES ARE TEMPORARY!!!")


decryption_failure_code = code(1)

login_step_1_code = code(2)

login_step_2_code = code(3)

time_limit_exceeded_code = code(4)

username_not_found_code = code(5)

username_found_code = code(6)

update_mailbox_code = code(7)

delete_email_code = code(8)

shred_mailbox_code = code(9)

close_account_code = code(10)

logout_code = code(11)

logout_successful_code = code(12)

logout_failed_code = code(13)

get_public_keys = code(14)

signup_code = code(15)

username_availability_check_code = code(16)

no_changes_in_mailbox = code(17)

invalid_username_code = code(18)

signup_successful_code = code(19)

invalid_signup_credentials = code(20)

okay_code = code(21)

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
