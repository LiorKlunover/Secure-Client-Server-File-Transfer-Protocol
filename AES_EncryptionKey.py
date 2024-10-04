from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64decode
import zlib

AES_KEY_SIZE = 32
class AES_EncryptionKey:
    def __init__(self):
        self.aes_key = get_random_bytes(AES_KEY_SIZE)  # AES-256 key
        self.iv = get_random_bytes(16)  # IV for CBC mode
        self.client_public_key = None
        self.checksum = 0

    # Receive the client's RSA public key base64 encoded
    def receive_rsa_public_key(self, public_key_data):
        try:
            decoded_key = b64decode(public_key_data)
            self.client_public_key = RSA.import_key(decoded_key)
            print("Public key received:", self.client_public_key)

        except (ValueError, IndexError, TypeError):
            raise ValueError("Invalid public key format")


    def get_aes_key(self):
        return self.aes_key

    #get the ebncrypted aes key by bytes
    def get_encrypted_aes_key(self) -> bytes:
        # Ensure that the client's public key is set
        if self.client_public_key is None:
            raise ValueError("Client's RSA public key not set.")

        # Create the cipher using the public key and PKCS1_OAEP padding
        cipher_rsa = PKCS1_OAEP.new(self.client_public_key)

        # Encrypt AES key + IV, ensure RSA key size is adequate
        combined_key_iv = self.aes_key + self.iv

        if len(combined_key_iv) > (self.client_public_key.size_in_bytes() - 42):  # 42 bytes overhead for OAEP padding
            raise ValueError("RSA key size too small to encrypt AES key and IV")

        encrypted_aes_key = cipher_rsa.encrypt(combined_key_iv)

        return encrypted_aes_key  # This returns the encrypted AES key + IV as bytes

    def decrypt_and_save_file(self, encrypted_file_data, filename: str):
        try:
            # Create AES cipher without padding
            cipher_aes = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

            # Decrypt without unpadding
            decrypted_file = cipher_aes.decrypt(encrypted_file_data)

            # Remove any padding if present (PKCS7)
            try:
                decrypted_file = unpad(decrypted_file, AES.block_size)
            except ValueError:
                # If unpadding fails, assume no padding was used
                pass

        except Exception as e:
            raise ValueError("Decryption failed - " + str(e))

        # Save decrypted file
        with open(filename, "wb") as file_out:
            file_out.write(decrypted_file)

        # Calculate checksum
        self.checksum = self.calculate_checksum_crc32(decrypted_file)
        return self.checksum

    def update_aes_key(self, new_aes_key):
        self.aes_key = new_aes_key

    # Return the checksum of the data crc32
    def calculate_checksum_crc32(self, data: bytes):
        return zlib.crc32(data)

# # Test the AES_EncryptionKey class
# public_key = "MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAlOnUMm2ESsbCUudERVTYcYhY4plU\nGIfuFt9mwXCNxbf1M5AXOfjTIpUw/ix3YhsFOo5fJDmE4gITc7uO58xvexEbMt3Dq5De2Hn8\nKlJSi1Q7VOk0pbz19HLN6edqPsh71MmRDKZy3K6k+NgK9spanx/NuRWXs53JtPKbdQ+Qbngc\nwrcHzIO4op3rjCfelCVraPOQn9FOzlZ7qcYXhe22B6w2p723W++2xXELa/FXtWbRBWE0Aolk\nQSYaqlcZdaKPB0JG7scEzHKLSncVIpSkpZxpmYAc/wh5tsBUZXJNE2IMp7hLPkWNiIF2SIjo\ngdu8F3UaBRNbMjw6nNWP8YsYpQIBEQ==\n"
# aes_key_obj = AES_EncryptionKey()
# aes_key_obj.receive_rsa_public_key(public_key)
# print(aes_key_obj.get_encrypted_aes_key())

# try:
#     with open("received_file.pdf", "rb") as file:
#         encrypted_file = file.read()
#         aes_key_obj = AES_EncryptionKey()
#
# except FileNotFoundError:
#     print("File not found")
