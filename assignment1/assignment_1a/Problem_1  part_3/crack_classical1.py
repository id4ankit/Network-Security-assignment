
import sys
from BitVector import * 
import string                                                      #(A)

# if len(sys.argv) != 2:                                                        #(B)
#     sys.exit('''Needs two command-line arguments, one for '''
#              '''the encrypted input message file and the other for the '''
#              '''decrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"               #(C)
print("Hello PassPhrase: ",PassPhrase)
print("My lengthis:      ",len(PassPhrase))     #My lengthis:       48
BLOCKSIZE = 64      
Num_bytes = BLOCKSIZE // 8 

Bit_Initiliaztion_vector= BitVector(bitlist=[0] * BLOCKSIZE)     

for i in range(0,len(PassPhrase)//Num_bytes):
    Text_str=PassPhrase[i*Num_bytes : (i+1)*Num_bytes]
    Bit_Initiliaztion_vector = Bit_Initiliaztion_vector ^ BitVector(textstring=Text_str)

print("PASSPHRASE After Xor:  ",Bit_Initiliaztion_vector)    #PASSPHRASE After Xor:   0011100100000010000111010101011000000111000111000101001001011111

#Open encrypted cypherfile
CipherFile=open('ciphertext.txt','r')
CipherText=CipherFile.read()
CipherFile.close()

print("Length of Ciphertext:",len(CipherText))  #3616
#print(CipherText)
CipherTextBV=BitVector(hexstring=CipherText)
print(CipherTextBV)
x=CipherTextBV._getsize()//BLOCKSIZE # without blocksize 14464 with blocksize 226
print("SIZE:  ",x)
# initializes an empty list named CipherBlock.
CipherBlock=[]
print(CipherTextBV._getsize()//Num_bytes)
for i in range(0,CipherTextBV._getsize(),BLOCKSIZE):
    CipherBlock.append(CipherTextBV[i : i + BLOCKSIZE])
print(len(CipherBlock))
#to print after appending all bitvector to cipherblock
# for i in range(len(CipherBlock)):
#     print(CipherBlock[i])

CipherBlock.insert(0,Bit_Initiliaztion_vector)
for i in range(len(CipherBlock)):
    print("Hello i am Cipherblock after insert Passphrase:",CipherBlock[i])

print(len(CipherBlock))
#array storing xors of plaintext blocks with key
CipherXORBlocks = []
for i in range(0,len(CipherBlock)-1):
    pxork = CipherBlock[i]^CipherBlock[i+1]
    CipherXORBlocks.insert(0,pxork)

print(len(CipherXORBlocks))
for i in range(len(CipherXORBlocks)):
    print("Hello i am Cipherblock after XOR:",CipherXORBlocks[i])


#  a list of dictionaries is initilize, each dictionary corresponding to a column
dict_list = [{} for _ in range(8)]

for i in range(8):

    for j in range(len(CipherXORBlocks)):
        temp=CipherXORBlocks[j]

        XORcipher_value=temp[i*Num_bytes : (i+1)*Num_bytes]
        XORcipher_str=str(XORcipher_value)

        if XORcipher_str not in dict_list[i]:
            dict_list[i][XORcipher_str]=1
        else:
            dict_list[i][XORcipher_str]+=1

for i, byte_dict in enumerate(dict_list):
    print(f"Frequency count for byte {i + 1} or column {i}:")
    for byte_value, frequency in byte_dict.items():
        print(f"Byte value: {byte_value}, Frequency: {frequency}")
    print()

sorted_dict_list = [sorted(d.items(), key=lambda x: x[1], reverse=True) for d in dict_list]

# Print the sorted dictionaries
for i, sorted_dict in enumerate(sorted_dict_list):
    print(f"Sorted dictionary {i + 1}:")
    for item in sorted_dict:
        print(item)
    print()


def max_frequency_item(dictionary):
    if not dictionary:
        return None, 0
    max_item = max(dictionary.items(), key=lambda x: x[1])
    return max_item

# Get the max frequency count with their corresponding elements from each dictionary
max_frequency_counts = [max_frequency_item(d) for d in dict_list]
keyBitVector= BitVector(size=0)
# Print the max frequency counts with their corresponding elements
# for i, (element, count) in enumerate(max_frequency_counts):
#     #print(f"Max frequency count and element in dictionary {i + 1}:")
#     #print(f"Element: {element}, Count: {count}")
#     #print()
#     keyBitVector.append(BitVector(bitstring=element)^BitVector(bitstring="01100101"))

for i, (element, count) in enumerate(max_frequency_counts):
    new_bitvector = BitVector(bitstring=element) ^ BitVector(bitstring="01100101")
    keyBitVector += new_bitvector

# Now keyBitVector contains the result of XOR operations
print(keyBitVector)

#Convert a binary string to an ASCII string.
def binStrToAsciiStr(binary_string):

    #    Parameters:- binary_string (str): The binary string to convert.
    #        Returns: - ascii_string (str): The ASCII string obtained from the binary string.
    # Split the binary string into 8-bit substrings
    substrings = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    # Convert each 8-bit substring to its corresponding ASCII character
    ascii_string = ''.join([chr(int(substring, 2)) for substring in substrings])
    return ascii_string
ans = ''
for i in range( len( CipherXORBlocks ) ):
    mystring = binStrToAsciiStr( str( keyBitVector ^ CipherXORBlocks[i] ) )
    ans += mystring
print(ans)

Final_FILEOUT = open( "recoveredtext.txt" , 'w')                                
Final_FILEOUT .write(ans)    
print(keyBitVector)
Final_FILEOUT .close() 