from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    # Padding to ensure the text is a multiple of 8 bytes
    padding_length = 8 - len(text) % 8
    padding = chr(padding_length) * padding_length
    return text + padding

def unpad(text):
    # Remove padding
    padding_length = ord(text[-1])
    return text[:-padding_length]

def des_encrypt(plaintext, key):
    # Ensure the key is 8 bytes long
    key = key.ljust(8)[:8]
    plaintext = pad(plaintext)
    iv = get_random_bytes(8)
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def des_decrypt(ciphertext, key):
    # Ensure the key is 8 bytes long
    key = key.ljust(8)[:8]
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:8]
    cipher = DES.new(key.encode('utf-8'), DES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[8:]).decode('utf-8')
    return unpad(plaintext)

# Example usage
plaintext = "HELLO"
key = "mysecret"
ciphertext = des_encrypt(plaintext, key)
print("Encrypted:", ciphertext)
decrypted_text = des_decrypt(ciphertext, key)
print("Decrypted:", decrypted_text)