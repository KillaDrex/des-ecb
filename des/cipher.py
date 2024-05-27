"""Functionality of DES implementation.

This module provides the classes and functions that facilitate the 
implementation of the DES algorithm based on the Electronic Code Book (ECB)
encryption/decryption scheme.

This module exports the following classes:
	Cipher    Represents the DES Algorithm

This module exports the following functions:
	xor                          Apply XOR operation on binary strings.
	binary_to_hex_str_64_bits    Convert binary string to hexadecimal string.
	hex_to_binary_str_64_bits    Convert hexadecimal string to binary string.
	validate_binary_str          Validate format of binary string.
	validate_hex_str             Validate format of hexadecimal string.
	group_characters             Separate string characters by space.

"""

import re

class Cipher:
	"""DES encryption algorithm using ECB scheme

	...

	Methods
	-------
	apply_permutation(binary_str, p)
		Apply permutation on binary string.
	encrypt_msg(msg, hex_key)
		Encrypt string message based on key.
	decrypt_msg(encrypted_data, hex_key)	
		Decrypt hexadecimal string based on key.

	"""

	# a class representing the Data Encryption Standard (DES) algorithm

	# permutations are based on 1-based indexing
	ip = [
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	]
	
	ip_inverse = [
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	]

	e_p = [
		32, 1, 2,  3,  4,  5,
		4, 5,  6,  7,  8,  9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1
	]

	tp_p = [
		16,  7, 20, 21,
		29, 12, 28, 17,
		1,  15, 23, 26,
		5,  18, 31, 10,
		2,   8, 24, 14,
		32,  27, 3, 9,
		19,  13, 30, 6,
		22,  11, 4, 25
	]

	key_p_1 = [
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4
	]

	key_p_2 = [
		14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	]

	# substitution boxes
	s_1 = {
		0: {0: 14, 1: 4, 2: 13, 3: 1, 4: 2, 5: 15, 6: 11, 7: 8, 8: 3, 9: 10, 10: 6, 11: 12, 12: 5, 13: 9, 14: 0, 15: 7},
		1: {0: 0, 1: 15, 2: 7, 3: 4, 4: 14, 5: 2, 6: 13, 7: 1, 8: 10, 9: 6, 10: 12, 11: 11, 12: 9, 13: 5, 14: 3, 15: 8},
		2: {0: 4, 1: 1, 2: 14, 3: 8, 4: 13, 5: 6, 6: 2, 7: 11, 8: 15, 9: 12, 10: 9, 11: 7, 12: 3, 13: 10, 14: 5, 15: 0},
		3: {0: 15, 1: 12, 2: 8, 3: 2, 4: 4, 5: 9, 6: 1, 7: 7, 8: 5, 9: 11, 10: 3, 11: 14, 12: 10, 13: 0, 14: 6, 15: 13},
	}

	s_2 = {
		0: {0: 15, 1: 1, 2: 8, 3: 14, 4: 6, 5: 11, 6: 3, 7: 4, 8: 9, 9: 7, 10: 2, 11: 13, 12: 12, 13: 0, 14: 5, 15: 10},
		1: {0: 3, 1: 13, 2: 4, 3: 7, 4: 15, 5: 2, 6: 8, 7: 14, 8: 12, 9: 0, 10: 1, 11: 10, 12: 6, 13: 9, 14: 11, 15: 5},
		2: {0: 0, 1: 14, 2: 7, 3: 11, 4: 10, 5: 4, 6: 13, 7: 1, 8: 5, 9: 8, 10: 12, 11: 6, 12: 9, 13: 3, 14: 2, 15: 15},
		3: {0: 13, 1: 8, 2: 10, 3: 1, 4: 3, 5: 15, 6: 4, 7: 2, 8: 11, 9: 6, 10: 7, 11: 12, 12: 0, 13: 5, 14: 14, 15: 9},
	}

	s_3 = {
		0: {0: 10, 1: 0, 2: 9, 3: 14, 4: 6, 5: 3, 6: 15, 7: 5, 8: 1, 9: 13, 10: 12, 11: 7, 12: 11, 13: 4, 14: 2, 15: 8},
		1: {0: 13, 1: 7, 2: 0, 3: 9, 4: 3, 5: 4, 6: 6, 7: 10, 8: 2, 9: 8, 10: 5, 11: 14, 12: 12, 13: 11, 14: 15, 15: 1},
		2: {0: 13, 1: 6, 2: 4, 3: 9, 4: 8, 5: 15, 6: 3, 7: 0, 8: 11, 9: 1, 10: 2, 11: 12, 12: 5, 13: 10, 14: 14, 15: 7},
		3: {0: 1, 1: 10, 2: 13, 3: 0, 4: 6, 5: 9, 6: 8, 7: 7, 8: 4, 9: 15, 10: 14, 11: 3, 12: 11, 13: 5, 14: 2, 15: 12},
	}

	s_4 = {
		0: {0: 7, 1: 13, 2: 14, 3: 3, 4: 0, 5: 6, 6: 9, 7: 10, 8: 1, 9: 2, 10: 8, 11: 5, 12: 11, 13: 12, 14: 4, 15: 15},
		1: {0: 13, 1: 8, 2: 11, 3: 5, 4: 6, 5: 15, 6: 0, 7: 3, 8: 4, 9: 7, 10: 2, 11: 12, 12: 1, 13: 10, 14: 14, 15: 9},
		2: {0: 10, 1: 6, 2: 9, 3: 0, 4: 12, 5: 11, 6: 7, 7: 13, 8: 15, 9: 1, 10: 3, 11: 14, 12: 5, 13: 2, 14: 8, 15: 4},
		3: {0: 3, 1: 15, 2: 0, 3: 6, 4: 10, 5: 1, 6: 13, 7: 8, 8: 9, 9: 4, 10: 5, 11: 11, 12: 12, 13: 7, 14: 2, 15: 14},
	}

	s_5 = {
		0: {0: 2, 1: 12, 2: 4, 3: 1, 4: 7, 5: 10, 6: 11, 7: 6, 8: 8, 9: 5, 10: 3, 11: 15, 12: 13, 13: 0, 14: 14, 15: 9},
		1: {0: 14, 1: 11, 2: 2, 3: 12, 4: 4, 5: 7, 6: 13, 7: 1, 8: 5, 9: 0, 10: 15, 11: 10, 12: 3, 13: 9, 14: 8, 15: 6},
		2: {0: 4, 1: 2, 2: 1, 3: 11, 4: 10, 5: 13, 6: 7, 7: 8, 8: 15, 9: 9, 10: 12, 11: 5, 12: 6, 13: 3, 14: 0, 15: 14},
		3: {0: 11, 1: 8, 2: 12, 3: 7, 4: 1, 5: 14, 6: 2, 7: 13, 8: 6, 9: 15, 10: 0, 11: 9, 12: 10, 13: 4, 14: 5, 15: 3},
	}

	s_6 = {
		0: {0: 12, 1: 1, 2: 10, 3: 15, 4: 9, 5: 2, 6: 6, 7: 8, 8: 0, 9: 13, 10: 3, 11: 4, 12: 14, 13: 7, 14: 5, 15: 11},
		1: {0: 10, 1: 15, 2: 4, 3: 2, 4: 7, 5: 12, 6: 9, 7: 5, 8: 6, 9: 1, 10: 13, 11: 14, 12: 0, 13: 11, 14: 3, 15: 8},
		2: {0: 9, 1: 14, 2: 15, 3: 5, 4: 2, 5: 8, 6: 12, 7: 3, 8: 7, 9: 0, 10: 4, 11: 10, 12: 1, 13: 13, 14: 11, 15: 6},
		3: {0: 4, 1: 3, 2: 2, 3: 12, 4: 9, 5: 5, 6: 15, 7: 10, 8: 11, 9: 14, 10: 1, 11: 7, 12: 6, 13: 0, 14: 8, 15: 13},
	}

	s_7 = {
		0: {0: 4, 1: 11, 2: 2, 3: 14, 4: 15, 5: 0, 6: 8, 7: 13, 8: 3, 9: 12, 10: 9, 11: 7, 12: 5, 13: 10, 14: 6, 15: 1},
		1: {0: 13, 1: 0, 2: 11, 3: 7, 4: 4, 5: 9, 6: 1, 7: 10, 8: 14, 9: 3, 10: 5, 11: 12, 12: 2, 13: 15, 14: 8, 15: 6},
		2: {0: 1, 1: 4, 2: 11, 3: 13, 4: 12, 5: 3, 6: 7, 7: 14, 8: 10, 9: 15, 10: 6, 11: 8, 12: 0, 13: 5, 14: 9, 15: 2},
		3: {0: 6, 1: 11, 2: 13, 3: 8, 4: 1, 5: 4, 6: 10, 7: 7, 8: 9, 9: 5, 10: 0, 11: 15, 12: 14, 13: 2, 14: 3, 15: 12},
	}

	s_8 = {
		0: {0: 13, 1: 2, 2: 8, 3: 4, 4: 6, 5: 15, 6: 11, 7: 1, 8: 10, 9: 9, 10: 3, 11: 14, 12: 5, 13: 0, 14: 12, 15: 7},
		1: {0: 1, 1: 15, 2: 13, 3: 8, 4: 10, 5: 3, 6: 7, 7: 4, 8: 12, 9: 5, 10: 6, 11: 11, 12: 0, 13: 14, 14: 9, 15: 2},
		2: {0: 7, 1: 11, 2: 4, 3: 1, 4: 9, 5: 12, 6: 14, 7: 2, 8: 0, 9: 6, 10: 10, 11: 13, 12: 15, 13: 3, 14: 5, 15: 8},
		3: {0: 2, 1: 1, 2: 14, 3: 7, 4: 4, 5: 10, 6: 8, 7: 13, 8: 15, 9: 12, 10: 9, 11: 0, 12: 3, 13: 5, 14: 6, 15: 11},
	}

	@classmethod
	def apply_permutation(cls, binary_str, p):

		"""Apply permutation on binary string and return result string.

		...

		Parameters
		----------
		binary_str : str
			Binary String.
		p : list
			Permutation list of integers.

		Returns
		-------
		str
			Permuted binary string.

		Raises
		------
		TypeError
			If the permutation list and/or its elements are invalid types.
		ValueError
			If the binary string is of invalid type or format.
			
		"""

		# validate binary string
		binary_str = validate_binary_str(binary_str)
		if binary_str == 'Invalid':
			raise ValueError('Not a valid binary String')

		# validate permutation list
		if type(p) != list:
			raise TypeError('Permutation not a List')
		for elem in p:
			if type(elem) != int:
				raise TypeError('Permutation element is not an Integer')

		result_binary_str = ''

		# apply permutation
		for index in p:
			# convert index to zero-based indexing
			index = index - 1

			result_binary_str = result_binary_str + binary_str[index]

		# return resulting binary string
		return result_binary_str

	@classmethod
	def encrypt_msg(cls, msg, hex_key):

		"""Encrypt string message and return encrypted string.

		...

		Parameters
		----------
		msg : str
			String message.
		hex_key : str
			Hexadecimal string.

		Returns
		-------
		str
			Encrypted message in hexadecimal format.

		Raises
		------
		TypeError
			If the string message is not a str.
		ValueError
			If the message is empty or key is invalid in type or format.
			
		"""

		# encrypt a string message (only supports 127 ascii character set)
		# returns ciphertext(in hexadecimal)
		# uses a 64-bit key in hexadecimal string
		# hexadecimal string must be 16-digits, and of proper format
		# hex string can have the prefix, 
		# casing is irrelevant, leading zeroes allowed
		# can raise TypeError|ValueError

		# validate msg to be a string
		if type(msg) != str:
			raise TypeError('Message not a string')
		elif len(msg) == 0:
			raise ValueError('Message contains no characters')

		# create key, validation is also done here
		key = Key(hex_key)

		# convert msg to 16-digit hexadecimal blocks
		hex_blocks_of_data = cls._convert_string_to_hexadecimal_in_64_bits_blocks(msg)

		# encrypt each block linearly
		ciphertext = ''
		for block in hex_blocks_of_data:
			ciphertext += cls._encrypt_hexadecimal(block, key)

		# return ciphertext
		return ciphertext

	@classmethod
	def decrypt_msg(cls, encrypted_data, hex_key):

		"""Decrypt hexadecimal string and return string message.

		...

		Parameters
		----------
		encrypted_data : str
			Encrypted string in hexadecimal format.
		hex_key : str
			Hexadecimal string.

		Returns
		-------
		str
			Original string message.

		Raises
		------
		ValueError
			If the encrypted string or key is of invalid type or format.
			
		"""

		# decrypts encrypted hexadecimal data 
		# returns string msg
		# uses a 64-bit key in hexadecimal string
		# encrypted hex string must be a multiple of 16 digits and of proper format
		# hex key string must be 16-digits, and of proper format
		# hex strings can have the prefix, 
		# casing is irrelevant, leading zeroes allowed
		# can raise ValueError

		# validate encrypted data
		encrypted_data = validate_hex_str(encrypted_data)
		if encrypted_data == 'Invalid':
			raise ValueError('Encrypted data must a hexadecimal String of proper format')
		elif len(encrypted_data) % 16 != 0:
			raise ValueError('Encrypted data is incomplete')

		# create key, validation is also done here
		key = Key(hex_key)

		# separate encrypted data into 16-digit blocks
		blocks = list()
		block = ''
		for digit in encrypted_data:
			# append digit to block
			block += digit

			# if block is filled, move to next
			if len(block) == 16:
				blocks.append(block) # append block
				block = '' # revert block

		# decrypt each block linearly
		decrypted_hex = ''
		for block in blocks:
			decrypted_hex += cls._decrypt_hexadecimal(block, key)

		# remove NUL characters (block padding) at the end of string
		decrypted_hex = re.sub('(00)+$', '', decrypted_hex)

		#return msg
		return cls._encode_hex_to_str(decrypted_hex)

	@classmethod
	def _encrypt_hexadecimal(cls, hex_data, key):
		# encrypts a 16-digit hex string, returns 16-digit encrypted hex string
		# casing is irrelevant
		# 0x/0X is recognized
		# leading zeroes from string are allowed

		# validate hex data & convert to 64 bits of binary
		bin_data = hex_to_binary_str_64_bits(hex_data)
		if bin_data == 'Invalid' or len(bin_data) != 64:
			raise ValueError('Data must be a valid hexadecimal and 64 bits')

		# validate key
		if type(key) != Key:
			raise TypeError('Key is not of type Key')

		# apply initial permutation
		bin_data = cls.apply_permutation(bin_data, cls.ip)

		# go through 16 rounds of encryption

		# split initial data
		l0 = bin_data[0:32]
		r0 = bin_data[32:]

		l_minus_1 = l0
		r_minus_1 = r0
		for i in range(1, 17):
			# get current round's data
			li = r_minus_1
			ri = xor(l_minus_1, 
				cls._apply_mangler_function(r_minus_1, key.round_keys[f'k{i}']) 
			)

			# update previous l and r for next round
			l_minus_1 = li
			r_minus_1 = ri

		# swap and apply inverse initial permutation on data
		encrypted_data = cls.apply_permutation(ri+li, cls.ip_inverse)

		# return encrypted data in hex string
		return binary_to_hex_str_64_bits(encrypted_data)

	@classmethod
	def _decrypt_hexadecimal(cls, encrypted_data, key):
		# decrypts a 16-digit encrypted hex string, returns 16-digit hex string
		# casing is irrelevant
		# 0x/0X is recognized
		# leading zeroes from string are allowed

		# validate encrypted data & convert to 64 bits of binary
		bin_data = hex_to_binary_str_64_bits(encrypted_data)
		if bin_data == 'Invalid' or len(bin_data) != 64:
			raise ValueError('Encrypted data must be a valid hexadecimal and 64 bits')

		# validate key
		if type(key) != Key:
			raise TypeError('Key is not of type Key')

		# apply initial permutation
		bin_data = cls.apply_permutation(bin_data, cls.ip)

		# go through 16 rounds of decryption

		# split initial data
		l0 = bin_data[0:32]
		r0 = bin_data[32:]

		l_minus_1 = l0
		r_minus_1 = r0
		for i in sorted(list(range(1, 17) ), reverse=True):
			# get current round's data
			li = r_minus_1
			ri = xor(l_minus_1, 
				cls._apply_mangler_function(r_minus_1, key.round_keys[f'k{i}']) 
			)

			# update previous l and r for next round
			l_minus_1 = li
			r_minus_1 = ri

		# swap and apply inverse initial permutation on data
		decrypted_data = cls.apply_permutation(ri+li, cls.ip_inverse)

		# return decrypted data in hex string
		return binary_to_hex_str_64_bits(decrypted_data)

	@classmethod
	def _apply_mangler_function(cls, r, k):
		# applies the f function on Rn-1,K1

		# apply expansion permutation on Rn-1
		r = cls.apply_permutation(r, cls.e_p)

		# apply K1 + E(Rn-1)
		r = xor(r, k)

		# apply substitution 
		r = cls._apply_substitution(r)

		# apply transposition
		r = cls.apply_permutation(r, cls.tp_p)

		# return f(Rn-1, K1)
		return r

	@classmethod
	def _apply_substitution(cls, binary_str):
		# applies the 8 substitutions on Kn+E(Rn-1 )

		s = 1
		b = ''
		result = ''
		for i in range(len(binary_str) ):
			# add current bit to b
			b += binary_str[i]

			# acquired Bn
			if len(b) == 6:
				# process Bn
				row = int(b[0] + b[5], base=2)
				column = int(b[1:5], base =2)

				# use appropriate substitution box
				match s:
					case 1:
						subs_value = cls.s_1[row][column]
					case 2:
						subs_value = cls.s_2[row][column]
					case 3:
						subs_value = cls.s_3[row][column]
					case 4:
						subs_value = cls.s_4[row][column]
					case 5:
						subs_value = cls.s_5[row][column]
					case 6:
						subs_value = cls.s_6[row][column]
					case 7:
						subs_value = cls.s_7[row][column]
					case 8:
						subs_value = cls.s_8[row][column]

				# convert decimal subs to binary string
				subs_value_bin = bin(subs_value)[2:]

				# add leading zeroes to substitution value if needed
				len_zeroes = 4 - len(subs_value_bin)
				for _ in range(len_zeroes):
					subs_value_bin = '0' + subs_value_bin

				# add Si(Bi) to result
				result += subs_value_bin

				# revert Bn
				b = ''

				# increment S
				s += 1

		# return result
		return result

	@classmethod
	def _convert_string_to_hexadecimal_in_64_bits_blocks(cls, string_val):
		# converts a string into hexadecimals and into 16-digits strings

		blocks = list()

		# go through each character in string
		block = ''
		for i in range(len(string_val) ):
			# get letter
			lttr = string_val[i]

			# get letter decimal value
			lttr_value = ord(lttr)

			# if value > 128 (a character outside of original ascii)
			if lttr_value > 128:
				raise ValueError('Only Original 127 bit ASCII characters are allowed')

			# convert lttr to 2 hexadecimal characters, emphasize lower case
			h = hex(lttr_value).replace('0x', '').lower()

			# add leading zero if necessary, to maintain the standard
			# of a byte per character (leading to supporting only the original ascii set)
			if len(h) != 2:
				h = '0' + h

			# append hexadecimal characters 
			block += h

			# check if block is packed, or last letter
			if (len(block) == 16) or (i == len(string_val) - 1):
				blocks.append(block)

				# revert block
				block = ''

		# check last block, pad it with zeroes if not 16-digits
		len_last_block = len(blocks[len(blocks)-1])

		if len_last_block != 16:
			len_zeroes = 16 - len_last_block

			for _ in range(len_zeroes):
				blocks[len(blocks)-1] += '0'

		# return blocks
		return blocks

	@classmethod
	def _encode_hex_to_str(cls, hex_str):
		# convert hex to letter str
		# returns str
		# hex string must be a multiple of 2 digits and of proper format
		# hex strings can have the prefix, 
		# casing is irrelevant

		# validate hex string
		hex_str = validate_hex_str(hex_str)
		if hex_str == 'Invalid':
			raise ValueError('Must be a hexadecimal String of proper format')
		elif len(hex_str) % 2 != 0:
			raise ValueError('Some character data is incomplete')

		# create a bytes object
		b = bytes.fromhex(hex_str)

		# go through each char byte, convert to letter
		str_value = ''
		for byte in b:
			str_value += chr(byte)

		return str_value

class Key:
	"""64-bit Key used in encryption/decryption.

	...

	Attributes
	----------
	binary_string
	keys_56_bit
	round_keys

	"""

	# a 64-bit read-only key

	# constructor accepts a 16-digit hex string
	# and converts it into 64 bits
	# casing is irrelevant
	# 0x/0X is recognized
	# leading zeroes from string are allowed
	def __init__(self, hex_str):
		# validate hex string & convert to 64 bits of binary 
		bin_str = hex_to_binary_str_64_bits(hex_str)

		# assign binary string of key
		self._bin_str = bin_str		

		# generate 56-bit keys
		self._56_bit_keys = self._generate_56_bit_keys()

		# generate 48-bit round keys
		self._generate_round_keys()
		self._48_bit_keys = self._generate_round_keys()

	# compares key 64-bit string to other binary string
	def __eq__(self, other):
		if type(other) != str:
			raise TypeError('Invalid operand type')

		# compare binary string to other string
		if self.binary_string == other:
			return True
		else:
			return False

	# generate 16 56-bit keys 
	# bit left shift circular is also done here
	def _generate_56_bit_keys(self):
		# permute 64 bit key
		binary_string_56_bit = Cipher.apply_permutation(self.binary_string, Cipher.key_p_1)

		# divide binary in half
		c0 = binary_string_56_bit[0:28]
		d0 = binary_string_56_bit[28:]
	
		# dictionary to hold 56-bit keys
		keys = dict()

		# round 0,1,8,15(1,2,9,16)=1 rest=2
		c_minus_1 = c0
		d_minus_1 = d0
		for i in range(16):
			match i:
				case 0 | 1 | 8 | 15:
					ci = c_minus_1[1:] + c_minus_1[0]
					di = d_minus_1[1:] + d_minus_1[0]
				case _:
					ci = c_minus_1[2:] + c_minus_1[0:2]
					di = d_minus_1[2:] + d_minus_1[0:2]

			# save key
			keys[f'c{i+1}'] = ci
			keys[f'd{i+1}'] = di

			# change previous to current
			c_minus_1 = ci
			d_minus_1 = di

		# return dictionary
		return keys

	# generate 16 48-bit round keys
	def _generate_round_keys(self):
		# dictionary
		round_keys = dict()

		# go through each of the 56 bit keys
		for i in range(1, 17):
			# combine halves to form key
			key = self.keys_56_bit[f'c{i}'] + self.keys_56_bit[f'd{i}']
			
			# generate round key
			round_key = Cipher.apply_permutation(key, Cipher.key_p_2)

			# add key to dictionary
			round_keys[f'k{i}'] = round_key

		# return dictionary 
		return round_keys

	@property
	def binary_string(self):
		"""Binary representation of key."""

		return self._bin_str

	@property 
	def keys_56_bit(self):
		"""Dictionary of permuted left-shifted 56-bit keys."""

		return self._56_bit_keys

	@property 
	def round_keys(self):
		"""Dictionary of round keys."""

		return self._48_bit_keys

def xor(first, second):
	"""Apply XOR operation on two binary strings.

	...

	Parameters
	----------
	first : str
		First binary string.
	second : str
		Second binary string.

	Returns
	-------
	str
		Result binary string.

	Raises
	------
	ValueError
		If the binary strings are invalid in type or format.
		
	"""

	# performs an XOR operation on two binary strings
	
	# validate binary strings
	first = validate_binary_str(first)
	second = validate_binary_str(second)

	if first == 'Invalid' or second == 'Invalid':
		raise ValueError("Invalid binary String")
	elif len(first) != len(second):
		raise ValueError('Binary Strings different in length')

	# go through each bit one by one
	result_str = ''
	for i in range(len(first) ):
		first_bit = first[i]
		second_bit = second[i]

		# if bits are the same, set new bit to 0, else 1
		if first_bit == second_bit:
			new_bit = '0'
		else:
			new_bit = '1'

		# append new bit to result
		result_str += new_bit

	# return result
	return result_str

def binary_to_hex_str_64_bits(binary_str):
	"""Convert binary string to hexadecimal.

	...

	Parameters
	----------
	binary_str : str
		Binary string.

	Returns
	-------
	str
		Hexadecimal string.

	Raises
	------
	ValueError
		If the binary string is invalid in format/type or not 64 characters.
		
	"""

	# convert binary string to hex str of 64 bits

	# validate binary string
	binary_str = validate_binary_str(binary_str)
	if binary_str == 'Invalid':
		raise ValueError('Not a valid binary String')
	elif len(binary_str) != 64:
		raise ValueError('Binary must be 64 bits')

	hex_str = ''
	b = ''
	for i in range(len(binary_str) ):
		# append bit
		b += binary_str[i]

		if len(b) == 4:
			# get hex digit from 4 bits
			h = hex(int(b, base=2) ).replace('0x', '')

			# append digit
			hex_str += h

			# revert b
			b = ''

	# return hex string, emphasize in lower-case
	return hex_str.lower()

def hex_to_binary_str_64_bits(hex_str):
	"""Convert hexadecimal string to binary.

	...

	Parameters
	----------
	hex_str : str
		Hexadecimal string.

	Returns
	-------
	str
		Binary string.

	Raises
	------
	ValueError
		If the hexadecimal string is invalid in format/type or not 16 characters.
		
	"""

	# convert hex string to binary str of 64 bits

	# validate hex string
	hex_str = validate_hex_str(hex_str)
	if hex_str == 'Invalid':
		raise ValueError('Not a valid hexadecimal String')
	elif len(hex_str) != 16:
		raise ValueError('Hexadecimal must be 64 bits')

	bin_str = bin(int(hex_str, 16) )[2:]

	# add leading zeroes if necessary
	len_zeroes = 64 - len(bin_str)

	# prefix binary string with leading zeroes if necessary
	for _ in range(len_zeroes):
		bin_str = '0' + bin_str

	# return binary string
	return bin_str

def validate_binary_str(binary_str):
	"""Validate binary string and return without prefix.

	...

	Parameters
	----------
	binary_str : str
		Binary string.

	Returns
	-------
	str
		Binary string.
		
	"""

	# validate binary string
	# returns binary string without prefix if valid

	if type(binary_str) != str:
		return 'Invalid'
	pattern = r'(?:0b)?([01]+)'
	match = re.fullmatch(pattern, binary_str, re.IGNORECASE)
	if not match:
		return 'Invalid'

	# return binary string without prefix
	return match.group(1)

def validate_hex_str(hex_str):
	"""Validate hexadecimal string and return without prefix.

	...

	Parameters
	----------
	hex_str : str
		Hexadecimal string.

	Returns
	-------
	str
		Hexadecimal string.
		
	"""

	# validate hex string
	# returns hex string without prefix if valid

	if type(hex_str) != str:
		return 'Invalid'
	pattern = r'(?:0x)?([a-f0-9]+)'
	match = re.fullmatch(pattern, hex_str, re.IGNORECASE)
	if not match:
		return 'Invalid'

	# return hex string with no prefix
	return match.group(1)

def group_characters(string_val, n):
	"""Separate characters in string with a space.

	...

	Parameters
	----------
	string_val : str
		Given string.
	n : int
		Number of characters in a group.

	Returns
	-------
	str
		Resulting string.

	Raises
	------
	TypeError
		If the string is not of type str, or n not of type int.
	ValueError
		If the string is empty, or n is negative/larger than string length.

	"""

	# group characters and separate by 1 space

	# validate string
	if type(string_val) != str:
		raise TypeError('Value is not a String')
	elif string_val == '':
		raise ValueError('String is empty')

	# validate n
	if type(n) != int:
		raise TypeError('n is not an Integer')
	elif not 0 < n <= len(string_val):
		raise ValueError('n is out of range')

	grouped_str = ''

	for i,lttr in enumerate(string_val):
		if i != 0 and i % n == 0:
			grouped_str = grouped_str + ' '

		grouped_str = grouped_str + lttr 

	return grouped_str