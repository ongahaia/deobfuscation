import builtins
file_in = r'xxxxxxx\06665b96e293b23acc80451abb413e50.sys'
file_out = r'xxxxxxxxxx\decrypted.bin'
address = 0x2569
key_addr= 0x80a
key_len = 8
size = 0x2ee
key = []  # Replace with your decryption key
result =[]

def xor_decrypt(data, key):
    for x in range (0 , 0x2ee):
        char_value = data[address + x]
        key_adj = x & 0x7
        key_chr = data[key_addr + key_adj]
        # data[address + x] = (data[address + x] ^ )
        #result.append (builtins.chr((key_chr ^ char_value)))
        #result.append ((key_chr ^ char_value))
        data[address + x] = (key_chr ^ char_value ^ x) & 0xff
    return data
    #return bytes(result)
# Open input file in binary mode
#with open(file_in, 'rb') as f:
    # Seek to address
    #f.seek(address)
    # Read data
 #   data = bytearray(f.read())
data = bytearray(open(file_in, 'rb').read())
#print (data)


key = data [key_addr:key_addr+key_len]

print (key)

# Decrypt data
modified_data = bytes(xor_decrypt(data, key))
print (modified_data)
# Write decrypted data to output file
with open(file_out, 'wb') as f:  # 'wb' for writing binary
    # Write zeros up to address
    #f.write(bytes(address))
    # Write decrypted data
    #f.seek(address)
    f.write(data)


#with open(file_out, 'r+b') as f:  # 'r+b' for reading and writing binary
    # Seek to address
 #   f.seek(address)
    # Write decrypted data
  #  f.write(decrypted_data)