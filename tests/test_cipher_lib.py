from des.cipher import group_characters, binary_to_hex_str_64_bits, hex_to_binary_str_64_bits, validate_binary_str, validate_hex_str, xor
import pytest 

def test_xor():
	# invalid cases
	with pytest.raises(ValueError): # not a string
		xor([], '1010')
	with pytest.raises(ValueError): # empty string
		xor('1010', '')
	with pytest.raises(ValueError): # not a valid binary string
		xor('12334', '12345')
	with pytest.raises(ValueError): # binary string with spaces
		xor('101010101 101010101', '1010')
	with pytest.raises(ValueError): # binary string with misplaced prefix
		xor('1010101010b000101010101', '1010')
	with pytest.raises(ValueError): # different length strings
		xor('101010', '1010')

	assert xor('000110110000001011101111111111000111000001110010', '011110100001010101010101011110100001010101010101') == '011000010001011110111010100001100110010100100111'
	
	# examples with 0b prefix
	assert xor('0b101010101010', '010101010101') == '111111111111'
	assert xor('111111110101011010101011', '101011110111001101101011') == '010100000010010111000000'

def test_binary_to_hex_str_64_bits():
	assert binary_to_hex_str_64_bits('0000000100100011010001010110011110001001101010111100110111101111') == \
	'0123456789aBCDEf'.lower()

	assert binary_to_hex_str_64_bits('0000000000000000000000000000000000000000000000000000000000000000') == '0000000000000000'

def test_hex_to_binary_str_64_bits():
	binary_string = '0000000100100011010001010110011110001001101010111100110111101111'

	assert hex_to_binary_str_64_bits('0123456789aBCDEf') == binary_string
	
	# example with 0x prefix
	assert hex_to_binary_str_64_bits('0x0123456789ABCDEF') == binary_string

def test_validate_binary_str():
	# invalid cases
	assert validate_binary_str([]) == 'Invalid' # not a string
	assert validate_binary_str('') == 'Invalid' # empty string
	assert validate_binary_str('12345') == 'Invalid' # not a valid binary string
	assert validate_binary_str('101010101 101010101') == 'Invalid' # binary string with spaces
	assert validate_binary_str('1010101010b000101010101') == 'Invalid' # binary string with misplaced prefix

	assert validate_binary_str('1100110000000000110011001111111111110000101010101111000010101010') == '1100110000000000110011001111111111110000101010101111000010101010'
	
	# example with 0b prefix
	assert validate_binary_str('0b1100110000000000110011001111111111110000101010101111000010101010') == '1100110000000000110011001111111111110000101010101111000010101010'

def test_validate_hex_str():
	# invalid cases
	assert validate_hex_str([]) == 'Invalid' # not a string
	assert validate_hex_str('') == 'Invalid' # empty string
	assert validate_hex_str('abcdefg') == 'Invalid' # not a valid hex string
	assert validate_hex_str('72 34') == 'Invalid' # hex string with spaces
	assert validate_hex_str('ab0x15') == 'Invalid' # hex string with misplaced prefix
	assert validate_hex_str('cat') == 'Invalid' # invalid format
	assert validate_hex_str('AX') == 'Invalid' # invalid format 

	assert validate_hex_str('133457799BBCDFF1') == '133457799BBCDFF1'

	# example with mixed casing
	assert validate_hex_str('0123456789aBCDEf') == '0123456789aBCDEf'
	
	# example with 0x prefix
	assert validate_hex_str('0x0123456789ABCDEF') == '0123456789ABCDEF'

def test_group_characters_invalid():
	# invalid string
	with pytest.raises(ValueError):
		group_characters('', 1)
	with pytest.raises(TypeError):
		group_characters(1.5, 1)
	with pytest.raises(TypeError):
		group_characters([], 1)	

	# invalid n
	with pytest.raises(TypeError):
		group_characters('a', 1.5)
	with pytest.raises(TypeError):
		group_characters('a', '')
	with pytest.raises(ValueError):
		group_characters('a', 0)
	with pytest.raises(ValueError):
		group_characters('a', 2)

def test_group_characters():
	assert group_characters('abcdefghijklmnopqrstuvwxyz', 2) == 'ab cd ef gh ij kl mn op qr st uv wx yz'
	assert group_characters('1111111111111111', 8) == '11111111 11111111'