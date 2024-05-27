"""Example of usage of package `des`"""

from des import Cipher, group_characters

def main():
	# Example - encrypt a message
	msg = 'Hi There!'
	key = '0x0123456789ABCDEF' # you can omit the prefix
	ciphertext = Cipher.encrypt_msg(msg, key)
	print('Ciphertext:', group_characters(ciphertext, 16) )

	# Example - decrypt a message
	msg_decrypted = Cipher.decrypt_msg(ciphertext, key)
	print('Message:', msg_decrypted)

if __name__ == '__main__':
	main()