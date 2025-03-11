# @category MyGhidra
def main():
	OP_TYPE_IMMEDIATE = 16384
	OP_TYPE_NO_CALL_REG = 512
	OP_TYPE_NO_CALL_STACK = 4202496
	#
	# declare target addresses for multiple crypto functions
	#

	# configuration values pulled from function where arg is pushed onto stack
	targetFuncEa1 = toAddr(0x406523)
	targetFuncEa2 = toAddr (0x004065b7)
	keyEa1 = toAddr(0x410120)
	ctEa1 = toAddr(0x40b930)
	ctLen1 = 0x36f5
	key_len= 0x40
	key1 = []
	ct = []
	ptDict1 = {}
	

	i = 0
	result1 = ''
	idx = 0    
	char_count = 0
	while (i < (ctLen1-0x1)):
		j = 0
		#print ('i is {}'.format(i))
		while True:
			key_byte = getByte(keyEa1.add((j + i) % 0x40))
			if key_byte < 0:
				keyuByte = chr((0xff - abs(key_byte) + 1))
			else:
				keyuByte= chr(key_byte)
			data_byte = getByte(ctEa1.add(i+j))
			if data_byte < 0:
				DatauByte = chr((0xff - abs(data_byte) + 1))
			else:
				DatauByte = chr(data_byte)
			#print ('data_byte  is {} and key_byte is {}'.format(data_byte, key_byte))
			if keyuByte == DatauByte:
				#print("************Found Target String ********")
				break
			j += 1
			decrypted_chr = chr(ord(keyuByte) ^ ord(DatauByte))
			result1 += decrypted_chr
			char_count += 1
		ptDict1[i] = result1
		i += (char_count +1)
		char_count = 0		
		result1 = ''
	#print(ptDict1)
	# for i, value in ptDict1.items():
	# 	print ('{}:{}'.format(i, value))
	
	# get xrefs to decryption function
	dec_func_xref = getReferencesTo(targetFuncEa1)
	for ref in dec_func_xref:
		if getInstructionAt((ref.getFromAddress())).getMnemonicString().lower() == 'call':
			pushing_inst = getInstructionAt((ref.getFromAddress())).getPrevious()
			if pushing_inst.getMnemonicString().lower() == 'push' and pushing_inst.getOperandType(0) == 16384:
				offset = pushing_inst.getOpObjects(0)[0].getValue()
				print ('offset {} is {}'.format(offset, ptDict1[offset]))
				setEOLComment(pushing_inst.getAddress(),ptDict1[offset])
			else:
				x = pushing_inst.getPrevious()
				if x.getMnemonicString().lower() == 'push' and x.getOperandType(0) == 16384:
					offset = x.getOpObjects(0)[0].getValue()
					print ('offset {} is {} from else'.format(offset, ptDict1[offset]))
					setEOLComment(x.getAddress(),ptDict1[offset])
				else:
					y = x.getPrevious()
					if y.getMnemonicString().lower() == 'push' and y.getOperandType(0) == 16384:
						offset = y.getOpObjects(0)[0].getValue()
						print ('offset {} is {} from else2'.format(offset, ptDict1[offset]))
						setEOLComment(y.getAddress(),ptDict1[offset])

	dec_func2_xref = getReferencesTo(targetFuncEa2)
	for ref in dec_func2_xref:
		if getInstructionAt((ref.getFromAddress())).getMnemonicString().lower() == 'call':
			moving_inst = getInstructionAt((ref.getFromAddress())).getPrevious()
			if moving_inst.getMnemonicString().lower() == 'mov' and moving_inst.getOperandType(0) == 512 and moving_inst.getOpObjects(0)[0].getName().lower()=='eax' and moving_inst.getOperandType(1) == 16384:
				offset = moving_inst.getOpObjects(1)[0].getValue()
				print ('offset {} is {}'.format(offset, ptDict1[offset]))
				setEOLComment(moving_inst.getAddress(),ptDict1[offset])
			# else:
			# 	x = pushing_inst.getPrevious()
			# 	if x.getMnemonicString().lower() == 'push' and x.getOperandType(0) == 16384:
			# 		offset = x.getOpObjects(0)[0].getValue()
			# 		print ('offset {} is {} from else'.format(offset, ptDict1[offset]))
			# 		setEOLComment(x.getAddress(),ptDict1[offset])
			# 	else:
			# 		y = x.getPrevious()
			# 		if y.getMnemonicString().lower() == 'push' and y.getOperandType(0) == 16384:
			# 			offset = y.getOpObjects(0)[0].getValue()
			# 			print ('offset {} is {} from else2'.format(offset, ptDict1[offset]))
			# 			setEOLComment(y.getAddress(),ptDict1[offset])







main()

# 004098c6     004041fc  passed through reg for decryptor 1

