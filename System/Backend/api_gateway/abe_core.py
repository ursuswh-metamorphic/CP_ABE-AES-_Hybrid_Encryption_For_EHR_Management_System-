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
        # Sửa lỗi: Thống nhất tên gọi thành self.abe
        self.abe = CPabe_BSW07(self.group)
        
    def setup(self):
        '''
        Thiết lập hệ thống CP-ABE bằng cách tạo khóa công khai (pk) và khóa chủ (mk)
        
        Trả về:
            tuple: (pk, mk) - khóa công khai và khóa chủ
        '''
        # Sửa lỗi: Gọi hàm trên self.abe
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
        # Sửa lỗi: Gọi hàm trên self.abe
        return self.abe.keygen(pk, mk, user_attributes)

    def encrypt(self, pk, plaintext, policy):
        '''
        Mã hóa dữ liệu với chính sách truy cập
        
        Tham số:
            pk: Khóa công khai
            plaintext (bytes): Dữ liệu cần mã hóa
            policy (str): Chuỗi biểu diễn chính sách truy cập (ví dụ: "Doctor AND Cardiologist")
            
        Trả về:
            dict: Bản mã chứa dữ liệu đã được mã hóa và thông tin chính sách
        '''
        try:
            sym_key = self.group.random(GT)
            
            # Mã hóa khóa đối xứng với CP-ABE
            original_abe_key = self.abe.encrypt(pk, sym_key, policy)
            if original_abe_key is None:
                raise ValueError("ABE encryption failed. Check the policy syntax.")

            # Đóng gói policy cùng với bản mã ABE
            packaged_abe_key = {
                'policy': policy,
                'ciphertext': original_abe_key
            }

            iv, sym_encrypted_data = self._symmetric_encrypt(sym_key, plaintext)
            
            return {
                'abe_key': packaged_abe_key, # Trả về gói mới
                'iv': iv,
                'data': sym_encrypted_data
            }
        except Exception as e:
            print(f"Encryption failed: {e}")
            traceback.print_exc()
            return None
    
    def decrypt(self, pk, sk, ct):
        '''
        Giải mã dữ liệu nếu thuộc tính của người dùng thỏa mãn chính sách
        
        Tham số:
            pk: Khóa công khai
            sk: Khóa bí mật của người dùng
            ct (dict): Bản mã từ hàm encrypt
            
        Trả về:
            bytes: Dữ liệu gốc nếu giải mã thành công, None nếu thất bại
        '''
        try:
            # Mở gói để lấy lại policy và bản mã ABE gốc
            packaged_abe_key = ct['abe_key']
            policy = packaged_abe_key['policy']
            original_abe_key = packaged_abe_key['ciphertext']

            # Giải mã khóa đối xứng bằng ABE, dùng policy vừa lấy được
            sym_key = self.abe.decrypt(pk, sk, original_abe_key, policy)
            
            if sym_key:
                print("[+] ABE Decryption SUCCESSFUL. Proceeding to symmetric decryption.")
                return self._symmetric_decrypt(sym_key, ct['iv'], ct['data'])

            print("[-] ABE Decryption FAILED. The secret key attributes do not satisfy the policy.")
            return None
        except Exception as e:
            print(f"[!] EXCEPTION during decryption: {e}") 
            traceback.print_exc()
            return None
        
    def _symmetric_encrypt(self, key, data):
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
    
    def _symmetric_decrypt(self, key, iv, encrypted_data):
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