from des.cipher import Key
import pytest

def test_init():
	# invalid cases
	with pytest.raises(ValueError): # not a string
		Key([])
	with pytest.raises(ValueError): # empty string
		Key('')
	with pytest.raises(ValueError): # not a valid hex string
		Key('abcdefg')
	with pytest.raises(ValueError): # hex string with spaces
		Key('72 34')
	with pytest.raises(ValueError): # hex string with misplaced prefix
		Key('ab0x15')
	with pytest.raises(ValueError):
		Key('cat') # invalid format
	with pytest.raises(ValueError):
		Key('AX') # invalid format 
	with pytest.raises(ValueError):
		Key('33333333333333333') # key larger than 64 bits
	with pytest.raises(ValueError): # key smaller than 64 bits
		Key('12345678912345')
	
	binary_string = '0000000100100011010001010110011110001001101010111100110111101111'

	# example with mixed casing
	assert Key('0123456789aBCDEf') == binary_string
	
	# example with 0x prefix
	assert Key('0x0123456789ABCDEF') == binary_string
	
	# example with leading zeroes
	assert Key('0000000000000000') == \
	'0000000000000000000000000000000000000000000000000000000000000000'
	
	assert Key('133457799BBCDFF1') == '0001001100110100010101110111100110011011101111001101111111110001'


def test_eq():
	# invalid case
	with pytest.raises(TypeError):
		Key('133457799BBCDFF1') == []

	assert Key('133457799BBCDFF1') == '0001001100110100010101110111100110011011101111001101111111110001'
	# example with a correct binary value but not 64-bit (wrong)
	assert not Key('133457799BBCDFF1') == '1001100110100010101110111100110011011101111001101111111110001'

def test_generate_56_bit_keys():
	sample_key = '133457799BBCDFF1'
	sample_key_2 = '0123456789ABCDEF'
	key = Key(sample_key)
	key_2 = Key(sample_key_2)

	assert key.keys_56_bit['c1'] == '1110000110011001010101011111'
	assert key.keys_56_bit['d1'] == '1010101011001100111100011110'
	assert key.keys_56_bit['c8'] == '0010101010111111110000110011'
	assert key.keys_56_bit['d8'] == '1001111000111101010101011001'
	assert key.keys_56_bit['c9'] == '0101010101111111100001100110'
	assert key.keys_56_bit['d9'] == '0011110001111010101010110011'
	assert key.keys_56_bit['c15'] == '1111100001100110010101010111'
	assert key.keys_56_bit['d15'] == '1010101010110011001111000111'
	assert key.keys_56_bit['c16'] == '1111000011001100101010101111'
	assert key.keys_56_bit['d16'] == '0101010101100110011110001111'

	assert key_2.keys_56_bit['c1'] == '1110000110011001010101000001'
	assert key_2.keys_56_bit['d1'] == '0101010110011001111000000001'
	assert key_2.keys_56_bit['c2'] == '1100001100110010101010000011'
	assert key_2.keys_56_bit['d2'] == '1010101100110011110000000010'
	assert key_2.keys_56_bit['c3'] == '0000110011001010101000001111'
	assert key_2.keys_56_bit['d3'] == '1010110011001111000000001010'
	assert key_2.keys_56_bit['c4'] == '0011001100101010100000111100'
	assert key_2.keys_56_bit['d4'] == '1011001100111100000000101010'
	assert key_2.keys_56_bit['c5'] == '1100110010101010000011110000'
	assert key_2.keys_56_bit['d5'] == '1100110011110000000010101010'	

def test_generate_round_keys():
	sample_key = '133457799BBCDFF1'
	sample_key_2 = '0123456789ABCDEF'
	key = Key(sample_key)
	key_2 = Key(sample_key_2)

	assert key.round_keys['k1'] == '000110110000001011101111111111000111000001110010'
	assert key.round_keys['k15'] == '101111111001000110001101001111010011111100001010'
	assert key.round_keys['k16'] == '110010110011110110001011000011100001011111110101'

	assert key_2.round_keys['k1'] == '000010110000001001100111100110110100100110100101'
