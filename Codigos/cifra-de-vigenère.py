import itertools
import string

def generate_key(text, key):
    key = list(key)
    if len(text) == len(key):
        return key
    else:
        for i in range(len(text) - len(key)):
            key.append(key[i % len(key)])
    return "".join(key)

def vigenere_encrypt(plaintext, key):
    key = generate_key(plaintext.replace(" ", ""), key)
    ciphertext = []
    for i in range(len(plaintext)):
        print("numero do texto:",ord(plaintext[i]))
        print("numero do key",ord(key[i]))
        x = (ord(plaintext[i]) + ord(key[i])) % 26
        print("soma:",x)
        x += ord('A')
        print("numero mudado:",x)
        print("letra mudada",chr(x))
        ciphertext.append(chr(x))
    return "".join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    key = generate_key(ciphertext, key)
    plaintext = []
    for i in range(len(ciphertext)):
        x = (ord(ciphertext[i]) - ord(key[i]) + 26) % 26
        x += ord('A')
        plaintext.append(chr(x))
    return "".join(plaintext)

## BRUTE FORCE
def generate_key_combinations(length):
    return itertools.product(string.ascii_uppercase, repeat=length)

def brute_force_vigenere(ciphertext, plaintext):
    Probability_keys = []
    Probability_plaintexts = []
    for key_length in range(1, len(ciphertext) + 1):
        print(f"Trying key length: {key_length}")
        for key_tuple in generate_key_combinations(key_length):
            key = ''.join(key_tuple)
            decrypted_text = vigenere_decrypt(ciphertext, key)
            print(f"Trying key: {key} -> Decrypted text: {decrypted_text}")
            # Add your own logic to check if the decrypted_text is the correct plaintext
            # For example, you can check if it contains only valid words or matches a known plaintext
            if is_valid_plaintext(decrypted_text.casefold()):
                Probability_keys.append(key)
                Probability_plaintexts.append(decrypted_text)
            print(Probability_keys)
            if len(Probability_keys) == 5:
                return Probability_keys, Probability_plaintexts
    return None, None

def is_valid_plaintext(decrypted_text):
    arquivo = '/home/roger/Documentos/Criptografia/Codigos/br-sem-acentos.txt'
    with open(arquivo, 'r') as file:
        content = file.read()
    words = content.split()
    same_length_words = [word for word in words if len(word) == len(decrypted_text)]
    for word in same_length_words:
        if word in decrypted_text:
            return True
    return False


# Example usage
plaintext = input("digite o texto:").upper()
key = input("digite o chave:").upper() 
ciphertext = vigenere_encrypt(plaintext, key)
print("Encrypted:", ciphertext)
print("Brute forcing")
decrypted_text = vigenere_decrypt(ciphertext, key).casefold()
print("Key",key)
print("Decrypted:", decrypted_text)
keys, plaintexts = brute_force_vigenere(ciphertext, plaintext)
print("Keys:", keys)
print("Plaintexts:", plaintexts)
