
"""Encrypt and decrypt a message and return result.

This script takes a 16-digit hexadecimal string as a key and 
either a plain or encrypted message for appropriate handling.

Running this tool requires the created package `des` in your environment.

"""

from des import Cipher, validate_hex_str
import sys,argparse

def main():
	# create parser
	parser = argparse.ArgumentParser(description=__doc__)

	# add arguments
	parser.add_argument('key', help='A 16-digit hexadecimal string representing a key')
	parser.add_argument('mode', help='(E)ncryption or (D)ecryption')
	parser.add_argument('input', help='A plain message or encrypted data represented as a hexadecimal string with character length as a multiple of 16.')

	# get arguments
	args = parser.parse_args()

	# validate key
	key = validate_hex_str(args.key)
	if key == 'Invalid':
		sys.exit('Invalid Key format - Must be proper Hexadecimal.')
	elif len(key) != 16: 
		sys.exit('Invalid Key format - Must be 16 digits.')

	# validate mode
	if args.mode.lower() not in ['e', 'd']:
		exit('Mode not recognized: Only (E)ncryption or (D)ecryption available.')

	# apply appropriate operations
	if args.mode.lower() == 'e':
		# validate message to only contain origina 127 bit ascii
		b = bytes(args.input, encoding='utf-8')
		for byte in b:
			if byte > 127:
				sys.exit('Script only supports original 127 bit ASCII characters.')

		# encrypt message
		ciphertext = Cipher.encrypt_msg(args.input, key)

		# print ciphertext
		print(f'Ciphertext: {ciphertext}')
	elif args.mode.lower() == 'd':
		# decrypt message
		try:
			msg = Cipher.decrypt_msg(args.input, key)
		except ValueError:
			sys.exit('Encrypted message is not of hexadecimal format with character length as a multiple of 16.')

		# print message
		print(f'Message: {msg}')

if __name__ == '__main__':
	main()
