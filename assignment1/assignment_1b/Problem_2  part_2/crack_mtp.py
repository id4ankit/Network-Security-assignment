import binascii

#cipher text is read from file
with open('ciphertext.txt', 'r') as f:
    ciphertexts = [binascii.unhexlify(line.rstrip()) for line in f]


# plaintext is simply initiliazed with "_"
Plaintexts=[ bytearray(b'_' * len(c)) for c in ciphertexts ]
Normaltexts = [bytearray(b'_' * len(c)) for c in ciphertexts]

# for ciphertext in ciphertexts :
#     print(str(ciphertext))

# for line in Plaintexts :
#     print(str(line)[12:-2])

#function is uesd for counting of alphabate
def COUNT_alphbate( char, position, ciphertexts ):
    count = 0
    for ciphertext in ciphertexts: 
        if len(ciphertext) > position:
            if chr(ciphertext[position]^char).isalpha(): 
                count=count+1
    return count

for column in range(max([len(ciphertext) for ciphertext in ciphertexts ])):
    for ciphertextline1 in ciphertexts:

        for ciphertextline2 in ciphertexts:

            if (len(ciphertextline1) > column ) and (len(ciphertextline2)> column):

                if chr(ciphertextline1[column] ^ ciphertextline2[column]).isalpha():

                    for k , c in enumerate(ciphertexts):

                        if len(c)>column:
                            # here it is check that if blank space contain in ciphertextline1 of given column 
                            if COUNT_alphbate(ciphertextline1[column], column,ciphertexts ) >= COUNT_alphbate(ciphertextline2[column],column,ciphertexts):
                                Plaintexts[k][column] = ciphertextline1[column] ^ 0b100000^c[column]     #  this portion: ' 0b100000^c[column]'   act as key for that particular column
                            else:
                                Plaintexts[k][column] = ciphertextline2[column] ^ 0b100000^c[column]    #  this portion: ' 0b100000^c[column]'   act as key for that particular column
                    break

for line in Plaintexts:
    # Convert bytearray to string and remove prefix and trailing quote
        print(str(line)[12:-2])

output_filename = "recovered.txt"  # Replace with your desired filename

with open(output_filename, 'w') as output_file:
    for line in Plaintexts:
        cleartext = str(line)[12:-2]
        output_file.write(cleartext + '\n')

print(f"Cleartexts extracted and write back to {output_filename}")


                                                           