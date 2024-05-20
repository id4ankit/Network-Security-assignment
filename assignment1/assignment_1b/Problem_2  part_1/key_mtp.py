#import secrets
import random
import string

# Alphbate KEY
def generate_MTP_Key(length):
    #"""Generate random keys for multi-time pad encryption."""
    characters = string.ascii_letters
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

# 
len = 12
random_key_string = generate_MTP_Key(len)
print("Random String:", random_key_string)

# #BINARY BIT KEY
# def generate_MTP_KEY(length):
#    # Generate random keys for multi-time pad encryption
#     binary_string = ''.join(secrets.choice('01') for _ in range(length))
#     return binary_string


# len = 20
# random_binary = generate_MTP_KEY(len)
# print("Random Binary_KEY_String:", random_binary)
