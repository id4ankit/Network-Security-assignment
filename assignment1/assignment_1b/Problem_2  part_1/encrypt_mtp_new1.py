from  key_mtp import generate_MTP_Key
from BitVector import BitVector

# read txt from input.txt
with open('input.txt', 'r') as file:
    paragraph = file.read()
# Split paragraph into sentences based on ' '
sentences = [sentence.strip() + '.' for sentence in paragraph.split('.')]

# Finding maximum length sentence
max_length = max(len(line) for line in sentences)
print("before padding :  ",max_length)

# Append '.' to make each sentence of equal length
# Equal_Length_Sentences = [sentence.ljust(max_length) for sentence in sentences]

# Print the sentences in different lists
# for line in Equal_Length_Sentences:
#     print(line)

# max_length_sentence = max(Equal_Length_Sentences, key=len)
# #print("The maximum length sentence is: ",max_length_sentence)
# length=len(max_length_sentence)
print("Its length is: ",max_length)

KEY=generate_MTP_Key(max_length)

# Write the key to a text file
File_Name = 'MTP_Key.txt'
with open(File_Name, 'w') as File:
    File.write(KEY)

print(KEY)
KEY_BV= BitVector(bitlist = [0]*max_length*8)
KEY_BV ^= BitVector( textstring = KEY )  
#print(KEY_BV)



XOR_SENTENCES=[]
# Iterate through each sentence
for sentence in sentences:
    len_sentence = len(sentence)
    XOR_length = min(len_sentence,max_length)
    
    sentence_BV = BitVector(bitlist = [0]*XOR_length*8)
    sentence_BV ^= BitVector(textstring=sentence[:XOR_length])

    # Initialize a BitVector XORresult to store the XOR'd result of sentence

    key__BV = BitVector(bitlist = [0]*XOR_length*8)
    key__BV ^=BitVector(textstring=KEY[:XOR_length])   

    XOR_Result = BitVector(bitlist = [0]*XOR_length*8)
    XOR_Result ^= sentence_BV ^ key__BV

    XOR_SENTENCES.append(XOR_Result.get_hex_string_from_bitvector())

for xor_sentence in XOR_SENTENCES:
    print(len(xor_sentence),": ",xor_sentence)


with open('output_file.txt','w') as file:
    for XOR_sentence in XOR_SENTENCES:
        file.write(XOR_sentence.strip() + '\n')

print(f"ENCRYPTED hex_text have been written to '{'output_file.txt'}'.")