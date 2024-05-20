
import sys
from BitVector import * 
import string                                                      #(A)

PassPhrase = "I want to learn cryptograph and network security"               #(C)
#print("Hello PassPhrase: ",PassPhrase)
#print("My lengthis:      ",len(PassPhrase))     #My lengthis:       48
BLOCKSIZE = 64      
Num_bytes = BLOCKSIZE // 8 

Bit_Initiliaztion_vector= BitVector(bitlist=[0] * BLOCKSIZE)     

for i in range(0,len(PassPhrase)//Num_bytes):
    Text_str=PassPhrase[i*Num_bytes : (i+1)*Num_bytes]
    Bit_Initiliaztion_vector = Bit_Initiliaztion_vector ^ BitVector(textstring=Text_str)

#print("PASSPHRASE After Xor:  ",Bit_Initiliaztion_vector)    #PASSPHRASE After Xor:   0011100100000010000111010101011000000111000111000101001001011111

#Open encrypted cypherfile
CipherFile=open('cipherinput.txt','r')
CipherText=CipherFile.read()
CipherFile.close()

#print("Length of Ciphertext:",len(CipherText))  #3616
#print(CipherText)
CipherTextBV=BitVector(hexstring=CipherText)
#print(CipherTextBV)
x=CipherTextBV._getsize()//BLOCKSIZE # without blocksize 14464 with blocksize 226
print("SIZE:  ",x)
# initializes an empty list named CipherBlock.
CipherBlock=[]
print(CipherTextBV._getsize()//Num_bytes)
for i in range(0,CipherTextBV._getsize(),BLOCKSIZE):
    #CipherBlock.append(CipherTextBV[i : i + BLOCKSIZE])
    CipherBlock.insert(0, CipherTextBV[i : i + BLOCKSIZE])
print(len(CipherBlock))
#to print after appending all bitvector to cipherblock
# for i in range(len(CipherBlock)):
#     print(CipherBlock[i])

CipherBlock.insert(0,Bit_Initiliaztion_vector)

#print(len(CipherBlock))
#array storing xors of plaintext blocks with key
CipherXORBlocks = []
for i in range(0,len(CipherBlock)-1):
    pxork = CipherBlock[i]^CipherBlock[i+1]
    CipherXORBlocks.insert(0,pxork)

#print(len(CipherXORBlocks))

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

sorted_dict_list = [sorted(d.items(), key=lambda x: x[1], reverse=True) for d in dict_list]


def max_frequency_item(dictionary):
    if not dictionary:
        return None, 0
    max_item = max(dictionary.items(), key=lambda x: x[1])
    return max_item

# Get the max frequency count with their corresponding elements from each dictionary
max_frequency_counts = [max_frequency_item(d) for d in dict_list]
keyBitVector= BitVector(size=0)

for i, (element, count) in enumerate(max_frequency_counts):
    new_bitvector = BitVector(bitstring=element) ^ BitVector(bitstring="00100000")
    keyBitVector += new_bitvector

# Now keyBitVector contains the result of XOR operations


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
#print(keyBitVector)
print(binStrToAsciiStr(str(keyBitVector)))
Final_FILEOUT .close() 