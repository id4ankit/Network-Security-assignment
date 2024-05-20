#!/usr/bin/env python

import sys
from BitVector import *                                                       #(A)

if len(sys.argv) != 3:                                                        #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted input message file and the other for the '''
             '''decrypted output file''')

PassPhrase = "I want to learn cryptograph and network security"               #(C)

BLOCKSIZE = 64                                                                #(D)
Num_bytes = BLOCKSIZE // 8 

Bit_Initiliaztion_vector= BitVector(bitlist=[0] * BLOCKSIZE)

for i in range(0 , len(PassPhrase)//Num_bytes):
    Text_Str = PassPhrase[ i * Num_bytes:(i + 1) * Num_bytes ]
    Bit_Initiliaztion_vector = Bit_Initiliaztion_vector ^ BitVector(textstring = Text_Str)


KEY = None
if sys.version_info[0]==3 :
    KEY= input ("\n ENTER KEY ->  ")
else:
    KEY= raw_input("\n ENTER KEY ->  ")
KEY=KEY.strip()

KEY_BIT_VECTOR = BitVector(bitlist=[0] * BLOCKSIZE)
for i in range(0,len(KEY)//Num_bytes):
    KEY_block  = KEY[i * Num_bytes : (i + 1) * Num_bytes]  # each time KEY value of BLOCKSIZE is store in KEY_BLOCK
    KEY_BIT_VECTOR =  KEY_BIT_VECTOR ^ BitVector(textstring =  KEY_block)



Decrypted_msg_Bit_Vector = BitVector(size=0)

Previous_block = Bit_Initiliaztion_vector
#Bit_Vector = BitVector(filename= sys.argv[1])

FILEIN = open(sys.argv[1])                                                  
Encrypted_bitVector = BitVector( hexstring = FILEIN.read() )

for i in range(0,len(Encrypted_bitVector)//BLOCKSIZE):
    Bit_Vector_Read = Encrypted_bitVector[i*BLOCKSIZE : (i + 1)*BLOCKSIZE]
    Temp_BV = Bit_Vector_Read.deep_copy()
    Bit_Vector_Read = Bit_Vector_Read ^ Previous_block
    Previous_block  = Temp_BV
    Bit_Vector_Read =  Bit_Vector_Read ^ KEY_BIT_VECTOR
    Decrypted_msg_Bit_Vector = Decrypted_msg_Bit_Vector + Bit_Vector_Read

DECRYPTED_TEXT = Decrypted_msg_Bit_Vector.get_text_from_bitvector()                     

# Write plaintext to the output file:

Output_File = open(sys.argv[2], 'w')                                            
Output_File.write(DECRYPTED_TEXT)                                                  
Output_File.close()                                                             