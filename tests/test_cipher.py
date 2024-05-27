from des.cipher import Cipher, Key
import pytest 
from Crypto.Cipher import DES

def test_encrypt_msg():
	# invalid cases - msg
	with pytest.raises(TypeError):
		Cipher.encrypt_msg([], '133457799BBCDFF1') # not a string msg
	with pytest.raises(ValueError):
		Cipher.encrypt_msg('', '133457799BBCDFF1') # empty string
	with pytest.raises(ValueError): # outside of original ascii character set
		Cipher._convert_string_to_hexadecimal_in_64_bits_blocks('€5 is all I have!')

	# invalid cases - key
	with pytest.raises(ValueError): # not a string
		Cipher.encrypt_msg('Hello', [])
	with pytest.raises(ValueError): # empty string
		Cipher.encrypt_msg('Hello', '')
	with pytest.raises(ValueError): # not a valid hex string
		Cipher.encrypt_msg('Hello', 'abcdefg')
	with pytest.raises(ValueError): # hex string with spaces
		Cipher.encrypt_msg('Hello', '72 34')
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Cipher.encrypt_msg('Hello', 'ab0x15')
	with pytest.raises(ValueError):
		Cipher.encrypt_msg('Hello', 'cat') # invalid format
	with pytest.raises(ValueError):
		Cipher.encrypt_msg('Hello', 'AX') # invalid format 
	with pytest.raises(ValueError):
		Cipher.encrypt_msg('Hello', '33333333333333333') # key larger than 64 bits
	with pytest.raises(ValueError): # key smaller than 64 bits
		Cipher.encrypt_msg('Hello', '12345678912345')
	
	# key 1 - example (lowercase key) (exact blocks)
	key_string = '133457799BBCDFF1'.lower()
	key = bytes.fromhex(key_string)
	cipher = DES.new(key, DES.MODE_ECB)
	
	plaintext = b'Writing programs (or programming) is a very crea'
	text = 'Writing programs (or programming) is a very crea'

	ciphertext_correct = cipher.encrypt(plaintext).hex()
	assert Cipher.encrypt_msg(text, key_string) == ciphertext_correct

	plaintext = b'Writing programs (or programming) is a very creative\nand rewarding activity.  You can write programs for'
	text = 'Writing programs (or programming) is a very creative\nand rewarding activity.  You can write programs for'

	ciphertext_correct = cipher.encrypt(plaintext).hex()
	assert Cipher.encrypt_msg(text, key_string) == ciphertext_correct

	# key 2 - example (mixed case key) (exact blocks)
	key_string = '0123456789AbCDeF'
	key = bytes.fromhex(key_string)
	cipher = DES.new(key, DES.MODE_ECB)
	
	plaintext = b'Writing programs (or programming) is a very crea'
	text = 'Writing programs (or programming) is a very crea'

	ciphertext_correct = cipher.encrypt(plaintext).hex()
	assert Cipher.encrypt_msg(text, key_string) == ciphertext_correct

	plaintext = b'Writing programs (or programming) is a very creative\nand rewarding activity.  You can write programs for'
	text = 'Writing programs (or programming) is a very creative\nand rewarding activity.  You can write programs for'

	ciphertext_correct = cipher.encrypt(plaintext).hex()
	assert Cipher.encrypt_msg(text, key_string) == ciphertext_correct


	# key 3 - example (key with prefix) (inexact blocks)
	key_string = '0xe9a3079306d23cb2'
	key = bytes.fromhex(key_string.replace('0x', '') )
	cipher = DES.new(key, DES.MODE_ECB)
	
	plaintext = b'Hello, there!, I am here!\x00\x00\x00\x00\x00\x00\x00'
	text = 'Hello, there!, I am here!'

	ciphertext_correct = cipher.encrypt(plaintext).hex()
	assert Cipher.encrypt_msg(text, key_string) == ciphertext_correct

	# large example (exact blocks)
 
	with open('tests/msg.txt') as file:
		text = file.read() + 'filler'
	plaintext = bytes(text, encoding='ascii')

	ciphertext_correct = cipher.encrypt(plaintext).hex()
	assert Cipher.encrypt_msg(text, key_string) == ciphertext_correct

def test_decrypt_msg():
	key_string = '0123456789AbCDeF'

	# invalid cases - decrypted data
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg([], key_string) # not a string
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg('', key_string) # empty string
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg('abcdefg', key_string) # not a valid hex string
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg('72 34', key_string) # hex string with spaces
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg('ab0x15', key_string) # hex string with misplaced prefix
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg('cat', key_string) # invalid format
	with pytest.raises(ValueError):
		assert Cipher.decrypt_msg('AX', key_string) # invalid format 
	with pytest.raises(ValueError): # incomplete bytes
		Cipher.decrypt_msg('AAAAA', key_string)

	# invalid cases - key
	hex_str = '546869732069732061206d6573736167652e'
	with pytest.raises(ValueError): # not a string
		Cipher.decrypt_msg(hex_str, [])
	with pytest.raises(ValueError): # empty string
		Cipher.decrypt_msg(hex_str, '')
	with pytest.raises(ValueError): # not a valid hex string
		Cipher.decrypt_msg(hex_str, 'abcdefg')
	with pytest.raises(ValueError): # hex string with spaces
		Cipher.decrypt_msg(hex_str, '72 34')
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Cipher.decrypt_msg(hex_str, 'ab0x15')
	with pytest.raises(ValueError):
		Cipher.decrypt_msg(hex_str, 'cat') # invalid format
	with pytest.raises(ValueError):
		Cipher.decrypt_msg(hex_str, 'AX') # invalid format 
	with pytest.raises(ValueError):
		Cipher.decrypt_msg(hex_str, '33333333333333333') # key larger than 64 bits
	with pytest.raises(ValueError): # key smaller than 64 bits
		Cipher.decrypt_msg(hex_str, '12345678912345')

def test_cipher_apply_permutation():
	sample_64_bit_binary_string = '0001001100110100010101110111100110011011101111001101111111110001'
	sample_64_bit_binary_string_p_1 = '11110000110011001010101011110101010101100110011110001111'
	sample_64_bit_binary_string_p_2 = '000110110000001011101111111111000111000001110010'
	sample_64_bit_binary_string_2 = '0000000100100011010001010110011110001001101010111100110111101111'

	# invalid cases
	with pytest.raises(ValueError): # not a string
		Cipher.apply_permutation([], Cipher.key_p_1)
	with pytest.raises(ValueError): # empty string
		Cipher.apply_permutation('', Cipher.key_p_1)
	with pytest.raises(ValueError): # not a valid binary string
		Cipher.apply_permutation('12345', Cipher.key_p_1)
	with pytest.raises(ValueError): # binary string with spaces
		Cipher.apply_permutation('101010101 101010101', Cipher.key_p_1)
	with pytest.raises(ValueError): # binary string with misplaced prefix
		Cipher.apply_permutation('1010101010b000101010101', Cipher.key_p_1)

	with pytest.raises(TypeError): # not a list 
		Cipher.apply_permutation(sample_64_bit_binary_string, 1.5)		
	with pytest.raises(TypeError): # list element not an integer
		Cipher.apply_permutation('10101', [1, 1.5])	


	# with prefix
	assert Cipher.apply_permutation(f'0b{sample_64_bit_binary_string}', Cipher.key_p_1) == sample_64_bit_binary_string_p_1
	assert Cipher.apply_permutation(f'0B{sample_64_bit_binary_string}', Cipher.key_p_1) == sample_64_bit_binary_string_p_1
	
	assert Cipher.apply_permutation(sample_64_bit_binary_string, Cipher.key_p_1) == sample_64_bit_binary_string_p_1

	key = Key('133457799BBCDFF1')
	assert Cipher.apply_permutation(key.keys_56_bit['c15']+key.keys_56_bit['d15'], Cipher.key_p_2) == '101111111001000110001101001111010011111100001010'
	assert Cipher.apply_permutation(key.keys_56_bit['c16']+key.keys_56_bit['d16'], Cipher.key_p_2) == '110010110011110110001011000011100001011111110101'

	assert Cipher.apply_permutation(sample_64_bit_binary_string_2, Cipher.ip) == '1100110000000000110011001111111111110000101010101111000010101010'

def test_encrypt_hexadecimal():
	key = Key('133457799BBCDFF1')

	# invalid cases - data
	with pytest.raises(ValueError): # not a string
		Cipher()._encrypt_hexadecimal([], key)
	with pytest.raises(ValueError): # empty string
		Cipher()._encrypt_hexadecimal('', key)
	with pytest.raises(ValueError): # not a valid hex string
		Cipher()._encrypt_hexadecimal('abcdefg', key)
	with pytest.raises(ValueError): # hex string with spaces
		Cipher()._encrypt_hexadecimal('72 34', key)
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Cipher()._encrypt_hexadecimal('ab0x15', key)
	with pytest.raises(ValueError):
		Cipher()._encrypt_hexadecimal('cat', key) # invalid format
	with pytest.raises(ValueError):
		Cipher()._encrypt_hexadecimal('AX', key) # invalid format 
	with pytest.raises(ValueError):
		Cipher()._encrypt_hexadecimal('33333333333333333', key) # hex string larger than 64 bits
	with pytest.raises(ValueError): # hex string smaller than 64 bits
		Cipher()._encrypt_hexadecimal('12345678912345', key)

	# invalid cases - key
	with pytest.raises(ValueError): # not a string
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key([]) )
	with pytest.raises(ValueError): # empty string
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('') )
	with pytest.raises(ValueError): # not a valid hex string
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('abcdefg') )
	with pytest.raises(ValueError): # hex string with spaces
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('72 34') )
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('ab0x15') )
	with pytest.raises(ValueError):
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('cat') ) # invalid format
	with pytest.raises(ValueError):
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('AX') ) # invalid format 
	with pytest.raises(ValueError):
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('33333333333333333') ) # hex string larger than 64 bits
	with pytest.raises(ValueError): # hex string smaller than 64 bits
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('12345678912345') )
	with pytest.raises(TypeError): # wrong type 
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', 1.5)
	with pytest.raises(TypeError): # wrong type 
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', '133457799BBCDFF1')

	assert Cipher()._encrypt_hexadecimal('0123456789ABCDEF', Key('133457799BBCDFF1') ) == '85E813540F0AB405'.lower()
	assert Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('AAAAAAAAAAAAAAAA') ) == '3042741186e9938d'.lower()

	# with prefix
	assert Cipher()._encrypt_hexadecimal('0x0123456789ABCDEF', Key('0x133457799BBCDFF1') ) == '85E813540F0AB405'.lower()
	assert Cipher()._encrypt_hexadecimal('133457799BBCDFF1', Key('0xAAAAAAAAAAAAAAAA') ) == '3042741186e9938d'.lower()

	# mixed case
	assert Cipher()._encrypt_hexadecimal('0123456789ABcDEf', Key('133457799BbCDFF1') ) == '85E813540F0AB405'.lower()
	assert Cipher()._encrypt_hexadecimal('133457799BBCDff1', Key('AAAaAAAAAaaAAAAA') ) == '3042741186e9938d'.lower()

def test_decrypt_hexadecimal():
	key = Key('133457799BBCDFF1')

	# invalid cases - data
	with pytest.raises(ValueError): # not a string
		Cipher()._decrypt_hexadecimal([], key)
	with pytest.raises(ValueError): # empty string
		Cipher()._decrypt_hexadecimal('', key)
	with pytest.raises(ValueError): # not a valid hex string
		Cipher()._decrypt_hexadecimal('abcdefg', key)
	with pytest.raises(ValueError): # hex string with spaces
		Cipher()._decrypt_hexadecimal('72 34', key)
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Cipher()._decrypt_hexadecimal('ab0x15', key)
	with pytest.raises(ValueError):
		Cipher()._decrypt_hexadecimal('cat', key) # invalid format
	with pytest.raises(ValueError):
		Cipher()._decrypt_hexadecimal('AX', key) # invalid format 
	with pytest.raises(ValueError):
		Cipher()._decrypt_hexadecimal('33333333333333333', key) # hex string larger than 64 bits
	with pytest.raises(ValueError): # hex string smaller than 64 bits
		Cipher()._decrypt_hexadecimal('12345678912345', key)

	# invalid cases - key
	with pytest.raises(ValueError): # not a string
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key([]) )
	with pytest.raises(ValueError): # empty string
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('') )
	with pytest.raises(ValueError): # not a valid hex string
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('abcdefg') )
	with pytest.raises(ValueError): # hex string with spaces
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('72 34') )
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('ab0x15') )
	with pytest.raises(ValueError):
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('cat') ) # invalid format
	with pytest.raises(ValueError):
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('AX') ) # invalid format 
	with pytest.raises(ValueError):
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('33333333333333333') ) # hex string larger than 64 bits
	with pytest.raises(ValueError): # hex string smaller than 64 bits
		Cipher()._decrypt_hexadecimal('133457799BBCDFF1', Key('12345678912345') )
	with pytest.raises(TypeError): # wrong type 
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', 1.5)
	with pytest.raises(TypeError): # wrong type 
		Cipher()._encrypt_hexadecimal('133457799BBCDFF1', '133457799BBCDFF1')

	assert Cipher()._decrypt_hexadecimal('85E813540F0AB405', Key('133457799BBCDFF1') ) == '0123456789ABCDEF'.lower()
	assert Cipher()._decrypt_hexadecimal('3042741186e9938d', Key('AAAAAAAAAAAAAAAA') ) == '133457799BBCDFF1'.lower()

	# with prefix
	assert Cipher()._decrypt_hexadecimal('0x85E813540F0AB405', Key('0x133457799BBCDFF1') ) == '0123456789ABCDEF'.lower()
	assert Cipher()._decrypt_hexadecimal('3042741186e9938d', Key('0xAAAAAAAAAAAAAAAA') ) == '133457799BBCDFF1'.lower()

	# mixed case
	assert Cipher()._decrypt_hexadecimal('85e813540f0Ab405', Key('133457799BbCDFF1') ) == '0123456789ABCDEF'.lower()
	assert Cipher()._decrypt_hexadecimal('3042741186e9938d', Key('AAAaAAAAAaaAAAAA') ) == '133457799BBCDff1'.lower()

def test_apply_mangler_function():
	r = '11110000101010101111000010101010'
	k = '000110110000001011101111111111000111000001110010'
	er = '00100011010010101010100110111011'

	assert Cipher._apply_mangler_function(r, k) == er

def test_apply_substitution():
	r = '011000010001011110111010100001100110010100100111'
	subs = '01011100100000101011010110010111'
	assert Cipher._apply_substitution(r) == subs

def test_convert_string_to_hexadecimal_in_64_bits_blocks():
	# invalid cases
	with pytest.raises(ValueError): # outside of original ascii character set
		Cipher._convert_string_to_hexadecimal_in_64_bits_blocks('€')

	# only a \n character
	assert Cipher._convert_string_to_hexadecimal_in_64_bits_blocks('\n')[0] == '0a00000000000000'

	# 1 block, less than 16 hexadecimal digits
	assert Cipher._convert_string_to_hexadecimal_in_64_bits_blocks('Hello')[0] == '48656c6c6f000000'
	
	# 1 block, exact 16 digits
	assert Cipher._convert_string_to_hexadecimal_in_64_bits_blocks('Hello, L')[0] == '48656C6C6F2C204C'.lower()
	
	# 1 block, more than 16 digits, less than 2 blocks
	blocks = Cipher._convert_string_to_hexadecimal_in_64_bits_blocks('Hello, Andre!')
	assert blocks[0] == '48656C6C6F2C2041'.lower()
	assert blocks[1] == '6E64726521000000'.lower()

	# more than 1 block, last block has less than 16 digits
	text = 'Writing programs (or programming) is a very creative\nand rewarding activity.  You can write programs for\nWHAT IS HAPPENING??'
	blocks_valid = ['57726974696E6720', '70726F6772616D73', '20286F722070726F', '6772616D6D696E67', '2920697320612076', '6572792063726561', '746976650A616E64', '2072657761726469', '6E67206163746976', '6974792E2020596F', '752063616E207772', '6974652070726F67', '72616D7320666F72', '0A57484154204953', '2048415050454E49', '4E473F3F00000000']

	blocks = Cipher._convert_string_to_hexadecimal_in_64_bits_blocks(text)

	for i in range(len(blocks_valid) ):
		block = blocks[i]
		block_valid = blocks_valid[i].lower()

		assert block == block_valid

	# more than 1 block, last block has exact 16 digits
	text = 'Writing programs (or programming) is a very creative\nand rewarding activity.  You can write programs for'
	blocks_valid = ['57726974696E6720', '70726F6772616D73', '20286F722070726F', '6772616D6D696E67', '2920697320612076', '6572792063726561', '746976650A616E64', '2072657761726469', '6E67206163746976', '6974792E2020596F', '752063616E207772', '6974652070726F67', '72616D7320666F72']
                      
	blocks = Cipher._convert_string_to_hexadecimal_in_64_bits_blocks(text)

	for i in range(len(blocks_valid) ):
		block = blocks[i]
		block_valid = blocks_valid[i].lower()

		assert block == block_valid

def _encode_hex_to_str():
	# invalid cases
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str([]) # not a string
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str('') # empty string
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str('abcdefg') # not a valid hex string
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str('72 34') # hex string with spaces
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str('ab0x15') # hex string with misplaced prefix
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str('cat') # invalid format
	with pytest.raises(ValueError):
		assert Cipher._encode_hex_to_str('AX') # invalid format 
	with pytest.raises(ValueError): # incomplete bytes
		Cipher._encode_hex_to_str('AAAAA')

	assert Cipher._encode_hex_to_str('486920546865726521') == 'Hi There!'

	# example with mixed casing
	assert Cipher._encode_hex_to_str('546869732069732061206D6573736167652e') == \
	'This is a message.'
	
	# example with 0x prefix
	assert Cipher._encode_hex_to_str('0x486920546865726521') == 'Hi There!'