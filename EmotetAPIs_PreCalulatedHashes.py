import sys
import os
import idc
import idautils
import idaapi

# ... (your existing global variables) ...
api_names_directory = r"C:\Users\malware\Desktop\Samples\Emotet"  #r"C:\Users\malware\Desktop\Samples\Kaspersky_Advanced_malware_analysis_framework\py_sources\py_sources"
f__get_API_address_2 = 0x18001C7BC
f__get_API_address_2_wrapper = 0x018001CC90

def get_API_hash(api_name):
	# ... (your existing get_API_hash function) ...
	ebx = 0x10
	r11 = 0x6
	r8 = 0x0
	# i = 0 # These two lines are global variables in your original script, consider scope if this function is called repeatedly
	# v6 = 0 # It's better to make them local if they are part of the hash calculation logic
	result = 0x0

	eax = 0
	for char in api_name:
		r9b = ord(char)
		eax = r8
		ecx = ebx
		edx = r8
		edx = (edx << ecx) & 0xFFFFFFFF
		ecx = r11
		eax = (eax << ecx) & 0xFFFFFFFF
		edx = (edx + eax) & 0xffffffff
		# sign extend - not needed as its ascii char
		#eax = r9b 
		if r9b & 0x80: # If the 8th bit is set, it's considered negative by movsx
			eax = (r9b | 0xFFFFFF00) # Sign extend to 32 bits
		else:
			eax = r9b
		edx = (edx + eax) & 0xFFFFFFFF
		edx = (edx - r8) & 0xffffffff
		r8 = edx
		eax = r8
	return eax

def get_fastcall_args(call_ea):
	# ... (your existing get_fastcall_args function) ...
	args = 0x0
	current = call_ea
	func_start = idaapi.get_func(call_ea).start_ea
	arg_value = 0
	insn = idc.prev_head(current)

	while insn != idc.BADADDR and insn >= func_start:
		mnem = idc.print_insn_mnem(insn)
		if mnem in ['mov', 'lea'] and idc.get_operand_type(insn, 0) == idc.o_reg and idc.print_operand(insn, 0) == 'edx':
			arg_value = idc.get_operand_value(insn, 1)
			break
		insn = idc.prev_head(insn)
	args = arg_value & 0xffffffff
	return args

def main():
	if api_names_directory not in sys.path:
		sys.path.append(api_names_directory)
	import api_names
	apis = api_names.api_names

	print("Pre-calculating API hashes...")
	# Create a dictionary to store {XORed_hash: api_name}
	api_hash_to_name = {}
	xor_key = 0x2D53E135 # Define the XOR key once

	for api in apis:
		calculated_hash = get_API_hash(api)
		xor_hash = calculated_hash ^ xor_key
		api_hash_to_name[xor_hash] = api
	#print(f"Pre-calculation complete. Stored {len(api_hash_to_name)} API hashes.")
		#print (f"api {api} has a hash of {xor_hash}")
	#print (api_hash_to_name)


	# # Process xrefs for f__get_API_address_2
	for xref in idautils.CodeRefsTo(f__get_API_address_2, False):
		current_api_hash = get_fastcall_args(xref)
		if current_api_hash in api_hash_to_name:
			api_name = api_hash_to_name[current_api_hash]
			print(f"Hash at offset {xref:x} is {current_api_hash:x}, API is {api_name}")
			idc.set_cmt(xref, api_name, 0)
		else:
			print(f"Hash {current_api_hash:x} at offset {xref:x} not found in pre-calculated list.")


	# Process xrefs for f__get_API_address_2_wrapper
	for xref2 in idautils.CodeRefsTo(f__get_API_address_2_wrapper, False):
		current_api_hash_wrapper = get_fastcall_args(xref2)
		if current_api_hash_wrapper in api_hash_to_name:
			api_name = api_hash_to_name[current_api_hash_wrapper]
			print(f"Hash at offset {xref2:x} is {current_api_hash_wrapper:x}, API is {api_name}")
			idc.set_cmt(xref2, api_name, 0)
		else:
		    print(f"Hash {current_api_hash_wrapper:x} at offset {xref2:x} not found in pre-calculated list.")

	print("DONEEEEEEEE")

main()