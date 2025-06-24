'''
Module abe_core.py
----------------
Cung cấp các hàm cơ bản để tích hợp CP-ABE (Ciphertext-Policy Attribute-Based Encryption) 
vào hệ thống quản lý truy cập.

CP-ABE cho phép mã hóa dữ liệu với các chính sách truy cập dựa trên thuộc tính.
Chỉ những người dùng có thuộc tính thỏa mãn chính sách mới có thể giải mã dữ liệu.

Dựa trên thuật toán CP-ABE của Bethencourt và Waters (2007).
'''

import os
import pickle
import base64
import hashlib
import traceback

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

class ABECore:
    '''
    Lớp chính cung cấp các phương thức để tạo khóa, mã hóa và giải mã dữ liệu sử dụng CP-ABE
    '''
    
    def __init__(self, curve='SS512'):
        '''
        Khởi tạo ABECore với một đường cong ghép cặp
        
        Tham số:
            curve (str): Loại đường cong ghép cặp được sử dụng (mặc định: 'SS512')
        '''
        self.group = PairingGroup(curve)
        self.abe = CPabe_BSW07(self.group)
        
    def setup(self):
        '''
        Thiết lập hệ thống CP-ABE bằng cách tạo khóa công khai (pk) và khóa chủ (mk)
        
        Trả về:
            tuple: (pk, mk) - khóa công khai và khóa chủ
        '''
        return self.abe.setup()
    
    def keygen(self, pk, mk, user_attributes):
        '''
        Tạo khóa bí mật cho người dùng dựa trên thuộc tính của họ
        
        Tham số:
            pk: Khóa công khai
            mk: Khóa chủ
            user_attributes (list): Danh sách thuộc tính của người dùng
            
        Trả về:
            sk: Khóa bí mật của người dùng
        '''
        return self.abe.keygen(pk, mk, user_attributes)

    def encrypt(self, pk, plaintext, policy):
        try:
            sym_key = self.group.random(GT)
            abe_encrypted_key = self.abe.encrypt(pk, sym_key, policy)
            if abe_encrypted_key is None:
                raise ValueError("ABE encryption failed. Check the policy syntax.")
            iv, sym_encrypted_data = self.symmetric_encrypt(sym_key, plaintext)
            return {
                'abe_key': abe_encrypted_key, 
                'iv': iv,
                'data': sym_encrypted_data
            }
        except Exception as e:
            print(f"Encryption failed: {e}")
            traceback.print_exc()
            return None
    
    def decrypt(self, pk, sk, ct):
        '''
        Giải mã ABE để lấy lại khóa đối xứng.
        Hàm này chỉ là một wrapper quanh hàm decrypt của thư viện.
        '''
        try:
            return self.abe.decrypt(pk, sk, ct)
        except Exception as e:
            print(f"[!] EXCEPTION during ABE decryption: {e}") 
            traceback.print_exc()
            return None

    def symmetric_encrypt_for_upload(self, data):
        '''
        Tạo khóa session (dk) và dùng nó để mã hóa dữ liệu bằng AES.
        Trả về một dict chứa khóa dk, iv và dữ liệu đã mã hóa.
        '''
        # Tạo khóa session key ngẫu nhiên
        dk = self.group.random(GT)
        iv, encrypted_data = self.symmetric_encrypt(dk, data)
        return {
            'dk': dk,
            'iv': iv,
            'data': encrypted_data
        }

    def symmetric_encrypt(self, key, data):
        '''
        Mã hóa dữ liệu với một khóa đối xứng (AES-CTR)
        '''
        h = hashlib.sha512()
        h.update(str(key).encode())
        aes_key = h.digest()[:32]
        
        iv = Random.new().read(AES.block_size)
        
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted_data = cipher.encrypt(data)
        
        return iv, encrypted_data
    
    def symmetric_decrypt(self, key, iv, encrypted_data):
        '''
        Giải mã dữ liệu với khóa đối xứng (AES-CTR)
        '''
        h = hashlib.sha512()
        h.update(str(key).encode())
        aes_key = h.digest()[:32]
        
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        
        return cipher.decrypt(encrypted_data)

    def serialize_key(self, key):
        '''
        Chuyển đổi một đối tượng khóa thành chuỗi bytes
        '''
        return objectToBytes(key, self.group)

    def deserialize_key(self, key_bytes):
        '''
        Khôi phục một đối tượng khóa từ chuỗi bytes
        '''
        return bytesToObject(key_bytes, self.group)

    def save_public_key(self, pk, filename_prefix='keys', directory='.'):
        '''
        Lưu khóa công khai vào file
        '''
        os.makedirs(directory, exist_ok=True)
        pk_bytes = self.serialize_key(pk)
        with open(os.path.join(directory, f"{filename_prefix}_public.key"), 'wb') as f:
            f.write(pk_bytes)

    def load_public_key(self, filename='keys_public.key', directory='.'):
        '''
        Tải khóa công khai từ file
        '''
        with open(os.path.join(directory, filename), 'rb') as f:
            pk_bytes = f.read()
        return self.deserialize_key(pk_bytes)

    def save_user_key(self, sk, filename, directory='.'):
        '''
        Lưu khóa bí mật của người dùng vào file
        '''
        os.makedirs(directory, exist_ok=True)
        sk_bytes = self.serialize_key(sk)
        with open(os.path.join(directory, filename), 'wb') as f:
            pickle.dump(sk_bytes, f)
    
    def load_user_key(self, filename, directory='.'):
        '''
        Tải khóa bí mật của người dùng từ file
        '''
        with open(os.path.join(directory, filename), 'rb') as f:
            sk_bytes = pickle.load(f)
        return self.deserialize_key(sk_bytes)