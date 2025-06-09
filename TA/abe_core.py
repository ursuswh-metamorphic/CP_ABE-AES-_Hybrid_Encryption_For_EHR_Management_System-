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
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.core.engine.util import objectToBytes, bytesToObject

# Import CP-ABE implementation
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup

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
        self.cpabe = CPabe_BSW07(self.group)
        
    def setup(self):
        '''
        Thiết lập hệ thống CP-ABE bằng cách tạo khóa công khai (pk) và khóa chủ (mk)
        
        Trả về:
            tuple: (pk, mk) - khóa công khai và khóa chủ
        '''
        return self.cpabe.setup()
    
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
        return self.cpabe.keygen(pk, mk, user_attributes)

    def serialize_key(self, key):
        return base64.b64encode(objectToBytes(key, self.group))

    def deserialize_key(self, b64_string):
        return bytesToObject(base64.b64decode(b64_string), self.group)
    
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
        # Tạo khóa đối xứng ngẫu nhiên
        sym_key = self.group.random(GT)
        
        # Mã hóa khóa đối xứng với CP-ABE
        abe_encrypted_key = self.cpabe.encrypt(pk, sym_key, policy)
        
        # Mã hóa dữ liệu với khóa đối xứng
        iv, sym_encrypted_data = self._symmetric_encrypt(sym_key, plaintext)
        
        # Trả về bản mã hoàn chỉnh
        return {
            'abe_key': abe_encrypted_key,
            'iv': iv,
            'data': sym_encrypted_data
        }
    
    def decrypt(self, pk, sk, ciphertext):
        '''
        Giải mã dữ liệu nếu thuộc tính của người dùng thỏa mãn chính sách
        
        Tham số:
            pk: Khóa công khai
            sk: Khóa bí mật của người dùng
            ciphertext (dict): Bản mã từ hàm encrypt
            
        Trả về:
            bytes: Dữ liệu gốc nếu giải mã thành công, None nếu thất bại
        '''
        try:
            # Giải mã khóa đối xứng với CP-ABE
            sym_key = self.cpabe.decrypt(pk, sk, ciphertext['abe_key'])
            
            if sym_key:
                # Giải mã dữ liệu với khóa đối xứng
                return self._symmetric_decrypt(sym_key, ciphertext['iv'], ciphertext['data'])
            return None
        except Exception as e:
            print(f"Decrypt error: {e}")
            return None
        
    def _symmetric_encrypt(self, key, data):
        '''
        Mã hóa dữ liệu với một khóa đối xứng (AES)
        
        Tham số:
            key: Khóa đối xứng 
            data (bytes): Dữ liệu cần mã hóa
            
        Trả về:
            tuple: (iv, encrypted_data) - vector khởi tạo và dữ liệu đã mã hóa
        '''
        # Chuyển khóa CP-ABE thành khóa AES bằng hàm băm
        h = hashlib.sha512()
        h.update(str(key).encode())
        aes_key = h.digest()
        
        # Tạo vector khởi tạo ngẫu nhiên
        iv = Random.new().read(AES.block_size)
        
        # Mã hóa với AES CTR mode
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        
        # Đảm bảo dữ liệu là bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted_data = cipher.encrypt(data)
        
        return iv, encrypted_data
    
    def _symmetric_decrypt(self, key, iv, encrypted_data):
        '''
        Giải mã dữ liệu với khóa đối xứng
        
        Tham số:
            key: Khóa đối xứng
            iv (bytes): Vector khởi tạo
            encrypted_data (bytes): Dữ liệu đã mã hóa
            
        Trả về:
            bytes: Dữ liệu gốc
        '''
        # Chuyển khóa CP-ABE thành khóa AES
        h = hashlib.sha512()
        h.update(str(key).encode())
        aes_key = h.digest()
        
        # Giải mã với AES CTR mode
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
        cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        
        return cipher.decrypt(encrypted_data)

    def save_public_key(self, pk, filename_prefix='keys', directory='.'):
        '''
        Lưu khóa công khai vào file, khóa chủ lưu trong AWS Secret Manager
        
        Tham số:
            pk: Khóa công khai
            filename_prefix (str): Tiền tố tên file
            directory (str): Thư mục lưu trữ
        '''
        os.makedirs(directory, exist_ok=True)
        
        # Chuyển đổi khóa thành bytes
        pk_encoded = self.serialize_key(pk)
        
        # Lưu khóa công khai
        with open(os.path.join(directory, f"{filename_prefix}_public.key"), 'wb') as f:
            f.write(pk_encoded)

    
    def load_public_key(self, filename='keys_public.key', directory='.'):
        '''
        Tải khóa công khai từ file
        
        Tham số:
            filename (str): Tên file chứa khóa công khai
            directory (str): Thư mục lưu trữ
            
        Trả về:
            Khóa công khai
        '''
        with open(os.path.join(directory, filename), 'rb') as f:
            pk_encoded = f.read()
        
        return self.deserialize_key(pk_encoded)

    
    def save_user_key(self, sk, filename, directory='.'):
        '''
        Lưu khóa bí mật của người dùng vào file
        
        Tham số:
            sk: Khóa bí mật 
            filename (str): Tên file
            directory (str): Thư mục lưu trữ
        '''
        os.makedirs(directory, exist_ok=True)
        
        # Chuyển đổi khóa thành bytes
        sk_bytes = objectToBytes(sk, self.group)
        
        # Lưu khóa bí mật
        with open(os.path.join(directory, filename), 'wb') as f:
            pickle.dump(sk_bytes, f)
    
    def load_user_key(self, filename, directory='.'):
        '''
        Tải khóa bí mật của người dùng từ file
        
        Tham số:
            filename (str): Tên file chứa khóa bí mật
            directory (str): Thư mục lưu trữ
            
        Trả về:
            Khóa bí mật của người dùng
        '''
        with open(os.path.join(directory, filename), 'rb') as f:
            sk_bytes = pickle.load(f)
            
        return bytesToObject(sk_bytes, self.group)

    
# Hàm tiện ích
def format_policy(policy_parts, operator='AND'):
    '''
    Định dạng danh sách các phần chính sách thành chuỗi chính sách hợp lệ
    
    Tham số:
        policy_parts (list): Danh sách các phần của chính sách
        operator (str): Toán tử kết hợp ('AND' hoặc 'OR')
        
    Trả về:
        str: Chuỗi chính sách đã định dạng
    '''
    if not policy_parts:
        return ""
    
    if len(policy_parts) == 1:
        return policy_parts[0]
    
    formatted_parts = []
    for part in policy_parts:
        if ' ' in part and not (part.startswith('(') and part.endswith(')')):
            formatted_parts.append(f"({part})")
        else:
            formatted_parts.append(part)
            
    return f" {operator} ".join(formatted_parts)