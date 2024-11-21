import socket
from DES import convertHextoBin, convertBintoHex, convertBintoDec, convertDectoBin, permute, shift_left, xor, initial_perm, exp_d, sbox, final_perm, encrypt, genKey, permut, encryptLongmsg, shift_left, xor, encrypt, genKey, permut, encryptLongmsg, decryptLongmsg, generateRoundKeys
from rsa_pka import rsa_decrypt

def loadPrivateKey():
    with open("private_key.txt", "r") as file:
        return map(int, file.read().split(","))

def serverProg():
    host = '127.0.0.1'
    port = 12345 
    
    d, n = loadPrivateKey()

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Server listening on {host}:{port}")

        conn, address = server_socket.accept()
        print(f"Server connected to {address}")

        encrypted_key = conn.recv(1024).decode()
        print(f"Generated random DES Key: ")
        des_key = rsa_decrypt(encrypted_key, d, n)
        print(f"Decrypted DES key: {des_key}")
        
        rkb, rk = generateRoundKeys(des_key)
        rkb_rev = rkb[::-1]
        rk_rev = rk[::-1]
        
        while True:
            encrypted_message = conn.recv(1024).decode()
            if not encrypted_message:
                print("No message received, closing connection.")
                break

            print(f"Received encrypted message from client: {encrypted_message}")

            plain_text = decryptLongmsg(encrypted_message, rkb_rev, rk_rev)
            print(f"Decrypted message: {plain_text}")
            
            conn.send(plain_text.encode())
            print("Decrypted message sent back to client.")

        conn.close()
        print("Connection closed.")
    except KeyboardInterrupt:
        print("\nServer stopped by user.")
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == '__main__':
    serverProg()