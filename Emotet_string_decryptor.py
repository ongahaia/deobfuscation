# https://malshare.com/sample.php?action=detail&hash=ed2640be5ed0a4486ecf7ac97b125e26b9d263624251eae1c9a42e9998ca1e68
import idc
import idautils
import idaapi

# the decrptor function is called in two ways:
#    directly or with in a wrapper that focues on resolving DDLs

def read_c_string(address):
	"""
	Reads a C-style null-terminated string from the given address.

	Args:
		address (int): The effective address (EA) where the string starts.

	Returns:
		str: The decoded string, or None if no string is found or decoding fails.
	"""
	s_bytes = bytearray()
	current_address = address
	max_read_length = 2048 # Safety limit to prevent infinite loops on malformed data

	for _ in range(max_read_length):
		byte_val = idaapi.get_byte(current_address)
		if byte_val == -1: # Invalid address or end of segment
			break
		if byte_val == 0x00: # Null terminator found
			break
		s_bytes.append(byte_val)
		current_address += 1
	return s_bytes #.decode('utf-8', errors='ignore')


def get_fastcall_args(call_ea):
	args = []
	args_offset = []
	current = call_ea
	func_start = idaapi.get_func(call_ea).start_ea  # Modern function getter
	 #for reg in arg_regs:
	arg_value = None
	insn = idc.prev_head(current)
	
	while insn != idc.BADADDR and insn >= func_start:
		mnem = idc.print_insn_mnem(insn)
		
		# Check for register assignment using modern operand API
		if mnem in ['mov', 'lea'] and idc.get_operand_type(insn, 0) == idc.o_reg and idc.print_operand(insn, 0) == 'rdx':
			#print ("found")
			arg_value = idc.print_operand(insn, 1)
			arg_address = hex(idc.get_operand_value(insn, 1))
			break
						
			# Get register name directly from operand text
			# target_reg = idc.print_operand(insn, 0)
			# if target_reg == reg:
			#     arg_value = idc.print_operand(insn, 1)
			#     break
				
		insn = idc.prev_head(insn)
	
	args.append(arg_value or "unknown")
	args_offset.append(arg_address)
	return args, args_offset


def get_fastcall_args2(call_ea):
	args = []
	args_offset = []
	current = call_ea
	func_start = idaapi.get_func(call_ea).start_ea  # Modern function getter
	 #for reg in arg_regs:
	arg_value = None
	insn = idc.prev_head(current)
	arg_address = 0x0
	while insn != idc.BADADDR and insn >= func_start:
		mnem = idc.print_insn_mnem(insn)
		
		# Check for register assignment using modern operand API
		if mnem in ['mov', 'lea'] and idc.get_operand_type(insn, 0) == idc.o_reg and idc.print_operand(insn, 0) == 'rcx':
			#print ("found")
			arg_value = idc.print_operand(insn, 1)
			arg_address = hex(idc.get_operand_value(insn, 1))
			break
						
			# Get register name directly from operand text
			# target_reg = idc.print_operand(insn, 0)
			# if target_reg == reg:
			#     arg_value = idc.print_operand(insn, 1)
			#     break
				
		insn = idc.prev_head(insn)
	
	args.append(arg_value or "unknown")
	args_offset.append(arg_address)
	return args, args_offset



def string_decryptor(blob):
	endianness = 'little' # Or 'big' if the data is big-endian
	#blob = '23C0AA3C34C0AA3C06B3F64E46A7D94A51F3981246B8CF1C01E5D91E03E5D94D88BDBF16254B22152E4B221556234E62443B4B3B41274E483194B4760000000000000000'
	
	#AA8BDA35A28BDA358FF8FF4684EEA250679B33DDF6E0A4F811277F2ADF00959E50B9A8CB678BE74565E70BD500000000
	#blob_bytes = bytes.fromhex(blob)
	key_bytes=blob[0:4]
	key = int.from_bytes(key_bytes, byteorder=endianness)
	# get the len
	

	# Extract the first DWORD (bytes 0-3)
	dword1_bytes = blob[0:4]
	# Convert the bytes to an integer
	dword1_int = int.from_bytes(dword1_bytes, byteorder=endianness)

	# Extract the second DWORD (bytes 4-7)
	dword2_bytes = blob[4:8]
	# Convert the bytes to an integer
	dword2_int = int.from_bytes(dword2_bytes, byteorder=endianness)

	# Perform the XOR operation
	xor_result_int = dword1_int ^ dword2_int

	# Convert the integer result back to 4 bytes (DWORD size)
	# You need to specify the length (4 for DWORD) and endianness
	xor_result_bytes = xor_result_int.to_bytes(4, byteorder=endianness)
	#v8 = (*v4 ^ v4[1])
	v10 = xor_result_int + 1

	# if ( (((*v4 ^ *(v4 + 4)) + 1) & 3) != 0 )
	# v10 = (v10 & 0xFFFFFFFC) + 4;

	if(((dword1_int ^ dword2_int)+1) & 3 != 0):
		v10 = (v10 & 0xFFFFFFFC) + 4 


	#print (f"{xor_result_int}")
	v15 = v10 >> 2 
	#print (f"{v10}    {v15}")
	blob_len = (4 * v15 + 3) >> 2
	# if encrypted_blob[0:4] > encrypted_blob[v15:4]:
	#     blob = 0
	dectypted_string = bytearray()
	#print (blob_len)
	encrypted_blob = blob[8:]
	#for i in range(0 , blob_len):
	for i in range(blob_len):

		en_dword = encrypted_blob[i*4:i*4 + 4]
		en_dword_int = int.from_bytes(en_dword, byteorder=endianness)
		#en_dword = int.from_bytes(en_dword, byteorder=endianness)
		de_dword_int = (en_dword_int ^ key)&0xffffffff
		st_byte = (de_dword_int & 0xff)# << 8) & 0xff00
		nd_byte = (de_dword_int >> 8) & 0xff #) & 0xff00
		rd_byte = (de_dword_int >> 16) & 0xff #) & 0xff00
		th_byte = (de_dword_int >> 24) & 0xff #) & 0xff00


		mod_de_word_int = de_dword_int & 0xff
		de_dword = de_dword_int.to_bytes(4, byteorder=endianness)
		de_dword_cpy = de_dword 
		#dectypted_string.extend(de_dword)


		dectypted_string.append(st_byte)
		dectypted_string.append(0x00)
		dectypted_string.append(nd_byte)
		dectypted_string.append(0x00)
		dectypted_string.append(rd_byte)
		dectypted_string.append(0x00)
		dectypted_string.append(th_byte)
		dectypted_string.append(0x00)


		#dectypted_string.append(\x00)
		#de_dword >>= 16


	full_decrypted_blob = bytes(dectypted_string)
	#b''.join(dectypted_string)
	#print(full_decrypted_blob)
	final_string = full_decrypted_blob.split(b'\x00\x00')[0].replace(b'\x00',b'')
	print(final_string)
	return final_string
	#print(type(final_string))

	#print(bytes(final_string).decode('utf-8'))



		

def main():
	decryptor_ea = 0x018001B924
	decryptor_wrapper_ea = 0x180008B0C

	for xref in idautils.CodeRefsTo(decryptor_ea, False):
		if xref == 0x180008b91:
			#print (f"Call at {xref:x} -> ecx is the value so go 1 level up in xref")
			continue
			
		args,args_offsets = get_fastcall_args(xref)
		print (f"Call at {xref:x} -> Args: {args} at offset {args_offsets}")
		read_addr = int(args_offsets[0],0)
		blob = read_c_string(read_addr)
		comment_ = string_decryptor(blob)
		idc.set_cmt(read_addr, comment_.decode('utf-8',errors='ignore'),0)
		idc.set_cmt(xref,comment_.decode('utf-8',errors='ignore'),0)
	
	for xref in idautils.CodeRefsTo(decryptor_wrapper_ea, False):
		args,args_offsets = get_fastcall_args2(xref)
		print (f"Call at {xref:x} -> Args: {args} at offset {args_offsets}")
		read_addr = int(args_offsets[0],0)
		blob = read_c_string(read_addr)
		comment_ = string_decryptor(blob)
		idc.set_cmt(read_addr, comment_.decode('utf-8',errors='ignore'),0)
		idc.set_cmt(xref,comment_.decode('utf-8',errors='ignore'),0)

	print ("DONE !!!!!!!!")
main()



# Args: {args:x} at offset {args_offsets:x}

# Call at 0x180016098 -> Args: ['txt_blob1'] at offset ['0x180001000']



# Args: {args:x} at offset {args_offsets:x}

# Call at 0x180016098 -> Args: ['txt_blob1'] at offset ['0x180001000']
