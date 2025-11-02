# import idaapi
#import idc
# import idautils
import re
import pefile
import struct
file = r"....SNAKE_GOLANG\ED3C05BDE9F0EA0F1321355B03AC42D0"
decrypted_string = ""
my_PE = pefile.PE(file)
with open(file, 'rb') as f:
		# 1. Read the entire file content as a 'bytes' object
	file_bytes = f.read()
		
		# 2. Convert the immutable 'bytes' object to a mutable 'bytearray'
	file_byte_array = bytearray(file_bytes)
# func_prolog = b"\x64\x8B\x0D\x14\x00\x00\x00" # mov     ecx, large fs:14h
# slice1= b"(" + b"\x8D\x05....\x89\x44\x24\x04\xC7\x44\x24\x08...." + b")"
#slice1 = b"(" + b"\x8D\x05....\x89\x44\x24\x04\xC7\x44\x24\x08....\xE8...." + b")"
#\x8D\x05\xA8\nc\x00\x89D$\x04\xC7\x44$\b`\x00\x00\x00
# xor_string = b"\x0F\xB6<\)1\xFE\x83\xFD" # movzx   edi, byte ptr [ecx+ebp]
# 											# xor     esi, edi
# 											# cmp     ebp,

# pattern = func_prolog + b".{10,100}" + slice1 + b".{10,100}" + slice1 + b".{10,100}" + xor_string #+ b".{10,20}"

start_func = b"\x64\x8B\x0D\x14\x00\x00\x00"
slice_string = b"(" + b"\x8D.....\x89.\$\x04\xC7\x44\$\b\x8d\x05.." + b")" 
slice_string2 = b"(" + b"\x8D.....\x89.\$\x04\xC7...\x8d\x05.." + b")"      
xor_loop = b"\x0F\xB6<\)1\xFE\x83\xFD" # movzx   edi, byte ptr [ecx+ebp]
                                            # xor     esi, edi
                                            # cmp     ebp,
#pattern = start_func + b".{10,100}" + slice_string + b".{10,100}" + slice_string + b".{10,100}" + xor_loop
pattern = start_func + b".{10,100}" + slice_string2 + b".{10,100}" + slice_string2 + b".{10,100}" + xor_loop
pat = re.compile(pattern, re.DOTALL|re.MULTILINE)
matches = pat.finditer(bytes(file_bytes))
#print ((matches))
with open(file + '_final2.idc', 'w+t') as idc: #create .idc script file to add comments and create string in the ida database
	idc.write("#include <idc.idc>\nstatic main(void) {\nauto f;\n")
	#idc.write(f"idc.set_func_cmt({hex(func_va)}, \"{decrypted_string}\", 0);\n")
	for m in matches:
		#print ("inside matches")
		func_va = my_PE.get_rva_from_offset (m.start()) + my_PE.OPTIONAL_HEADER.ImageBase
		#print(m.start(1)) #address of the first capture group
		#m_rva = my_PE.get_rva_from_offset( m.start()) + my_PE.OPTIONAL_HEADER.ImageBase     # pe.get_rva_from_offset(raw) + self.ImageBase
		#print(hex(m_rva))
		#print(hex(my_PE.get_rva_from_offset( m.start(1))+ my_PE.OPTIONAL_HEADER.ImageBase))
		string1_va = my_PE.get_rva_from_offset( m.start(1)) +2+ my_PE.OPTIONAL_HEADER.ImageBase
		if (string1_va + 4) > (my_PE.OPTIONAL_HEADER.ImageBase + len(file_bytes)-1):
			print (f"caution at offset {hex(string1_va)}")
			continue
		#print (f"string1_va is {hex(string1_va)} and  ")
		string1_va = struct.unpack("<L", file_bytes[m.start(1) +2 : m.start(1) +2 + 4])[0]
		string2_va = struct.unpack("<L", file_bytes[m.start(2) +2 : m.start(2) +2 + 4])[0]
		string1_len_va = string1_va + 0xE
		string_len = struct.unpack("<L", file_bytes[m.start(1) + 0xE : m.start(1) + 0xE + 4])[0]
		if string_len > 0xff:
			print(f"func: {func_va}  ")

		string1_raw = my_PE.get_offset_from_rva(string1_va - my_PE.OPTIONAL_HEADER.ImageBase)
		string2_raw = my_PE.get_offset_from_rva(string2_va - my_PE.OPTIONAL_HEADER.ImageBase)

		#decrypting loop
		decrypted_string = ""
		for i in range (string_len):
			decrypted_string += chr((((file_bytes[string1_raw+i] + i*2) ^ file_bytes[string2_raw +i])) & 0xff)
		#print (decrypted_string)
		#print(f"// Decrypted string: {decrypted_string}, inside func: {hex(func_va)}")
		file_byte_array[string1_raw:string1_raw+string_len] = decrypted_string.encode('utf-8')
		file_byte_array[string2_raw:string2_raw+string_len] = b"\x20"*string_len

		idc.write(f"del_items({hex(string1_va)},0,{hex(string_len)});\n") # undefine then 
		idc.write(f"create_strlit({hex(string1_va)},{hex(string_len)});\n") #create string in the ida db
		idc.idc.set_cmt(func_va, decrypted_string, 0)
		decrypted_string.replace('\x00', '[NULL]').encode('utf-8', errors='ignore').decode('utf-8')

		#print(f"// Decrypted string: {decrypted_string}, inside func: {hex(func_va)} str len: {hex(string_len)}")
		safe_string = decrypted_string.replace('\\', '\\\\')
		idc.write(f"idc.set_func_cmt({hex(func_va)}, r\"{safe_string}\", 0);\n")
		idc.write(f"idc.wait_for_next_event(2,0);\n") # because the list is HUGE it caused a problem with ida db so wait before next action
		


	idc.write("}\n")

		#my_PE.get_rva_from_offset( m.start(2))+2+ my_PE.OPTIONAL_HEADER.ImageBase
	#print (hex(string1_va_2))
	#string1 = 
	
	#print(f"{hex(string1_va_2)}")
#print ((matches.__next__)
with open(file + '.dec', 'wb') as outf:
	outf.write(file_byte_array)
    
print ("Done")
#print (f"len of file {len(file_bytes)}")
