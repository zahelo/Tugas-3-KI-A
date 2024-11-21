import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# generate key RSA
def generateRSAKeys():
    p = 281
    q = 277
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # nilai umum untuk e
    while gcd(e, phi) != 1:
        e = random.randint(2, phi)

    d = pow(e, -1, phi)
    return (e, n), (d, n)

def rsa_encrypt(message, e, n):
    m = int.from_bytes(message.encode(), 'big')  # Ubah pesan menjadi integer
    c = pow(m, e, n)  # Enkripsi RSA
    return hex(c)[2:].upper()  # Mengembalikan sebagai string heksadesimal

def rsa_decrypt(ciphertext, d, n):
    # Konversi dari hexadecimal string ke integer
    m = pow(int(ciphertext, 16), d, n)  # Menggunakan basis 16 untuk dekripsi RSA
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()


# menyimpan key RSA yang sudah di-generate
def saveKeys(public_key, private_key):
    with open("public_key.txt", "w") as pub_file:
        pub_file.write(f"{public_key[0]},{public_key[1]}")
    with open("private_key.txt", "w") as priv_file:
        priv_file.write(f"{private_key[0]},{private_key[1]}")

if __name__ == "__main__":
    public_key, private_key = generateRSAKeys()
    saveKeys(public_key, private_key)
    print("RSA keys generated and saved.")
