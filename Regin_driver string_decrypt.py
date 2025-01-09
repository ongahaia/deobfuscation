import builtins

buffer_size = 750
for x in range [750]:
    chr = buff[x]
    key_adj = x & 7
    key_chr = key [key_adj]
    result = key_chr ^ chr
    x+=1

for x in range (0x2ee):
    char_value = idc.get_wide_byte(buff_add+x)
    key_adj = x & 7
    key_chr = idc.get_wide_byte(key_add+key_adj)
    result.append (builtins.chr((key_chr ^ char_value) & 0Xff))
    #result.append (builtins.chr((char_value ^ key[x % key_len] ^ x) & 0Xff))
    #result.append (chr(int((key_chr ^ char_value) ,16)))
    
    result += chr((key_chr ^ char_value))
for i in range(len(result)):
    print(builtins.chr(result[i]), end='')