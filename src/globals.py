from pathlib import Path


# GLOBAL VARIABLES

SIGNATURE_DENOTER = b'\x00' #10101010

HASH_DENOTER = b'\xff'     #01010101

SERVER = "server"

SERVER_IP = "127.0.0.1"

SERVER_PORT = 9000

USER_HOME = str(Path.home())+'/'

CCR_FOLDER = ".ccr/"

RANDOM_NAME_LENGTH = 16 # CHARACTERS IN HEX

NONCE_SIZE = 32

HASH_SIZE = 32

# UNIX TIMESTAMPS
TIMESTAMP_SIZE = 4

MAX_USERNAME_SIZE = 64

MESSAGE_ID_SIZE = 2

REQUEST_SIZE = 2

RESPONSE_SIZE = 2

ROLLING_ID_SIZE = 8

ROLLING_AUTHENTICATION_TOKEN_SIZE = 32

KEY_FINGERPRINT_SIZE = 64

MAX_ADDRESS_LIST_SIZE = 100

DMZ_BUFFER_SIZE = 32768

HOUR = 60 * 60
STRANGER_TTL = 10 * 60

REQUEST_FILTER_0 = (4, 10)
REQUEST_FILTER_1 = (20, 60)
REQUEST_FILTER_2 = (200, 60*15)
REQUEST_FILTER_3 = (400, 60*60)
REQUEST_FILTER_4 = (2000, 60*60*12)


# TO BE FETCHED FROM THE DATABASE OF CLIENTS!
MAX_EMAILS_PER_HOUR = 20
MAX_EMAILS_PER_DAY = 100

MAX_ALLOWABLE_TIME_DELTA = 90 # SECONDS

SUPPORTED_VERSIONS = [b'\x00\x00']


def code(n):
	return (n).to_bytes(2, byteorder='little')


DECRYPTION_FAILURE = code(1)

LOGIN_STEP_1 = code(2)

LOGIN_STEP_2 = code(3)

TIME_LIMIT_EXCEEDED = code(4)

USERNAME_NOT_FOUND = code(5)

USERNAME_FOUND = code(6)

UPDATE_MAILBOX = code(7)

DELETE_EMAIL = code(8)

SHRED_MAILBOX = code(9)

CLOSE_ACCOUNT = code(10)

LOGOUT = code(11)

LOGOUT_SUCCESSFUL = code(12)

LOGOUT_FAILED = code(13)

GET_PUBLIC_KEYS = code(14)

SIGNUP = code(15)

USERNAME_AVAILABILITY_CHECK = code(16)

NO_CHANGES_IN_MAILBOX = code(17)

INVALID_USERNAME = code(18)

SIGNUP_SUCCESSFUL = code(19)

INVALID_SIGNUP_CREDENTIALS = code(20)

OKAY = code(21)

UNSUPPORTED_VERSION = code(22)

LOGIN = code(23)

SERVER_ERROR = code(24)

SIGNUP_FAILED = code(25)
