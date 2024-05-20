 
from BitVector import BitVector

# read key txt from MTP_Key.txt
with open('MTP_Key.txt', 'r') as file:
    KEY = file.read()
print("KEY: ",KEY)
# Load the encrypted data from encrypted_file.txt
KEY_len=len(KEY)
print(KEY_len)

# with open('output_file.txt', 'r') as f:
#     encrypted_data = f.read()
# print("ENCRYPTED DATA: \n")
# print(encrypted_data)
# x=len(encrypted_data)
# #for i in range(len(encrypted_data)):
    
# print(x)

# CipherTextBV=BitVector(hexstring=CipherText)

def binStrToAsciiStr(binary_string):

    #    Parameters:- binary_string (str): The binary string to convert.
    #        Returns: - ascii_string (str): The ASCII string obtained from the binary string.
    # Split the binary string into 8-bit substrings
    substrings = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    # Convert each 8-bit substring to its corresponding ASCII character
    ascii_string = ''.join([chr(int(substring, 2)) for substring in substrings])
    return ascii_string

# DECRYPT_SENTENCES=''

# with open('output_file.txt', 'r') as f:
#     # Read each line separately
#     for line in f:
#         # Remove any leading/trailing whitespaces and split the line into hexadecimal values
#         hex_values = line.strip().split('\n')
    
#         print("-----------size of hex_value---------:")
#         for hex_value in hex_values:
#             print("Length of hex_value:",)
#             XOR_length = min( len(hex_value)//2,KEY_len)

#             sentence_BV = BitVector(bitlist = [0]*XOR_length*8)
#             sentence_BV ^= BitVector(textstring=hex_value[:XOR_length])
#             print("-----------sentence:",len(sentence_BV),"  :",sentence_BV)
#             # Initialize a BitVector XORresult to store the XOR'd result of sentence

#             key__BV = BitVector(bitlist = [0]*XOR_length*8)
#             key__BV ^=BitVector(textstring=KEY[:XOR_length])
#             print("-----------KEY_BV:",len(key__BV),"  :",key__BV)

#             XOR_Result = BitVector(bitlist = [0]*XOR_length*8)
#             #XOR_Result ^= sentence_BV ^ key__BV
#             mystring=binStrToAsciiStr( str(sentence_BV ^ key__BV) )
#             #DECRYPT_SENTENCES.append(XOR_Result.get_bitvector_in_ascii())
#             DECRYPT_SENTENCES += mystring

# #final_text = ''.join(DECRYPT_SENTENCES)
# print("Final Text:", DECRYPT_SENTENCES)



def decrypt_hex(hex_value):
    # Convert hex value to BitVector
    hex_value_bv = BitVector(hexstring=hex_value)

    # Get the appropriate length for XOR operation
    XOR_length = min(len(hex_value_bv.get_bitvector_in_ascii()), KEY_len)

    # Perform XOR decryption
    decrypted_bv = hex_value_bv ^ BitVector(textstring=KEY[:XOR_length])

    # Convert the decrypted BitVector to a string using UTF-8 encoding
    decrypted_text = decrypted_bv.get_bitvector_in_ascii()

    return decrypted_text

# Open the file for reading
# with open('output_file.txt', 'r') as f:
#     # Read each line separately
#     for line in f.read().split('\n'):
#         # Remove any leading/trailing whitespaces and split the line into hexadecimal values
#         hex_values = line.strip()
#         # Iterate over each hexadecimal value
#         # for hex_value in hex_values:
#         decrypted_text = decrypt_hex(hex_values)
#         print("Decrypted Text:", decrypted_text)

with open('output_file.txt', 'r') as f, open('Decrypted_output_file.txt', 'w') as output_file:
    # Read each line separately
    for line in f:
        # Remove any leading/trailing whitespaces and split the line into hexadecimal values
        hex_values = line.strip().split()
        decrypted_text = ""
        # Iterate over each hexadecimal value
        for hex_value in hex_values:
            decrypted_text += decrypt_hex(hex_value) + " "
        # Write the decrypted text to the output file
        output_file.write(decrypted_text.strip() + '\n')
        print("Decrypted Text:", decrypted_text)

print(f"DECRYPTED plain_text have been written to '{'Decrypted_output_file.txt'}'.")  

