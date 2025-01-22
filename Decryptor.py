# this is a decryptor for the encrypted strings in the speedtest.sys sample

import idc, idaapi, idautils
import builtins
import ida_kernwin
ida_kernwin.set_encoding("UTF-16LE")

decryptor1_ea = 0x11432
decryptor1_wrapper_ea = 0x11524
decryptor1_seed = 0x0AA107FB
decryptor1_xrefs=[] #2nd and 5th calls the string is 3 ins above
string_arg = ""
def decryptor1(string_arg, string_ea):
    string_offset = string_arg
    string_call = string_ea
    
        # 1. Insert the seed value here
    seed = 0x0AA107FB
    i = 0
    result= ""
    while True:
        seed = ((seed * 0x19660D) + 0x3C6EF35F) & 0xFFFFFFFF # <-- 2. Replace None with a dynamic expression to calculate the seed
        val = idc.get_wide_word(string_offset+ i) # read 1 word
        if val == 0:
            break
        val = ( val ^ ( ( seed >> 16 ) | 0x8000 ) ) & 0xFFFF
        i = i + 2
        result += chr(val)
    print (result)
    idc.set_cmt(string_offset, None,0)
    idc.set_cmt(string_offset, result,0)
    idc.set_cmt(string_call, None,0)
    idc.set_cmt(string_call, result,0)

def trigger():
    for addr in idautils.CodeRefsTo(decryptor1_wrapper_ea, 0):
        print (hex(addr))
        decryptor1_xrefs.append(addr)
        if (addr == 0x10b35 or addr == 0x11011): #3rd and 5th
            string_ea = idc.prev_head(idc.prev_head(idc.prev_head(addr)))
            # idc.print_operand(ea, long n)
            string_arg = idc.get_operand_value(string_ea, 0)
            print (hex(string_ea) + " " + hex(string_arg))
            decryptor1(string_arg, string_ea)
            # call decryptors(string_arg)
        else:
            string_ea = idc.prev_head(idc.prev_head(addr))
            string_arg = idc.get_operand_value(string_ea, 0)
            print (hex(string_ea) + " " + hex(string_arg))
            decryptor1(string_arg, string_ea)
            # call decryptors(string_arg)


# decoder2 is doing the decoding is called only from wrapper_Aux
# wrapper_aux has 3xrefs one of them decrpter2_wrapper which has 6 xrefs
# 
decryptor2_ea = 0x11482
decryptor2_wrapper_aux_ea = 0x114CC # to get the args 0x00011598 is special
decryptor2_wrapper_ea = 0x11582
decryptor2_seed = 0x0AA107FB
decryptor2_xrefs=[] #(0x111b3 0x111B3 0x11CFF two stepps to get the address of the string) 0x11598 is the same as 0x111b3

for addr in idautils.CodeRefsTo(decryptor2_wrapper_ea, 0):
    decryptor2_xrefs.append(hex(addr))
for addr in idautils.CodeRefsTo(decryptor2_wrapper_aux_ea, 0):
    decryptor2_xrefs.append(hex(addr))


def decryptor2(string_arg, string_ea): #string_ea is the call address and string arg is the stored address
    string_offset = string_arg
    string_call = string_ea
    
        # 1. Insert the seed value here
    seed = 0x0AA107FB
    i = 0
    result= ""
    while True:
        seed = ((seed * 0x19660D) + 0x3C6EF35F) & 0xFFFFFFFF # <-- 4. Replace None with a dynamic expression to calculate the seed
        val = idc.get_wide_byte(string_offset+ i)
        if val == 0:
            break
        val = ( val ^ ( ( seed >> 16 ) | 0x80 ) ) & 0xFF
        i = i + 1
        result += chr(val)
    print (result)
    idc.set_cmt(string_offset, None,0)
    idc.set_cmt(string_offset, result,0)
    idc.set_name(string_offset, result, SN_CHECK)
    idc.set_cmt(string_call, None,0)
    idc.set_cmt(string_call, result,0)



def trigger2():
    for addr in decryptor2_xrefs: #strings type
        print (addr)
        if (addr == hex(0x11598)):
            continue
        if (addr == hex(0x111b3) or addr == hex(0x11CFF) or addr == hex(0x11cf2)): #(0x111b3 0x11cf2 0x11CFF two stepps to get the address of the string) 0x11598 is the same as 0x111b3
            string_ea = idc.prev_head(idc.prev_head(idc.prev_head(int(addr, 16))))
            # idc.print_operand(ea, long n)
            string_arg = idc.get_operand_value(string_ea, 0)
            print (hex(string_ea) + " " + hex(string_arg))
            decryptor2(string_arg, string_ea)
            # call decryptors(string_arg)
        else:
            string_ea = idc.prev_head(idc.prev_head(int(addr, 16)))
            string_arg = idc.get_operand_value(string_ea, 0)
            print (hex(string_ea) + " " + hex(string_arg))
            decryptor2(string_arg, string_ea)
            # call decryptors(string_arg)
                

decryptor3_ea = 0x12330
Decryptor3_key = 0x77
encrypted_String3=""
encrypted_string3_ea = [0x12B80 , 0x12B08, 0x12AA0, 0x12A40, 0x12BF8]
decrypted_string3 = ""
for ea in encrypted_string3_ea:
    i = 0
    decrypted_string3 = ""
    while True:
        val = idc.get_wide_word(ea + i)
        if val == 0:
            break
        val = (val ^ 0x7777) & 0xffff
        i += 2
        decrypted_string3 += chr(val)
    print(hex(ea))
    print (decrypted_string3)
    for xref in idautils.XrefsTo(ea, 1):
        idc.set_cmt(xref.frm, None,0)
        idc.set_cmt(xref.frm, decrypted_string3,0)
        

    for xrefs in idautils.DataRefsTo(ea):
        idc.set_cmt(ea, None,0)
        idc.set_cmt(ea, decrypted_string3,0)

    
    idc.set_name(ea, decrypted_string3, SN_CHECK)
    
# decryption encrypted_string[i] ^ 0x7777 i += 2
for i in encrypted_String3:
    val = encrypted_String3[i]
    
    decrypted_string3[i] = val
    i += 2



