# -*- coding: utf-8 -*-
"""
Module: new_abe_core.py (v19 - Final Secure Version)
--------------------------------------------------------------
Phiên bản nâng cấp và an toàn của hệ thống mã hóa dựa trên thuộc tính.

Thay đổi trong v19:
- Đồng bộ hóa lớp ABECompatWrapper và ví dụ sử dụng với logic
  ký metadata mới (chống replay/misuse attacks).
- Sửa lỗi và hoàn thiện luồng mã hóa/giải mã.
"""

import os
import logging
import traceback
import base64
import json
from datetime import datetime, timezone, timedelta

# Sử dụng Cryptodome là phiên bản kế thừa an toàn và được duy trì của PyCrypto
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA512

# Thư viện Charm cho mã hóa ABE
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

# Thư viện OQS cho chữ ký hậu lượng tử
import oqs

# === PHẦN 1: LỚP LÕI AN TOÀN (ABECoreGCM) ===

class ABEError(Exception):
    """Lớp ngoại lệ cơ bản cho các lỗi liên quan đến ABE."""
    pass

class SignatureVerificationError(ABEError):
    """Lỗi khi xác thực chữ ký hậu lượng tử thất bại."""
    pass

class DecryptionPolicyError(ABEError):
    """Lỗi khi thuộc tính của khóa riêng không thỏa mãn chính sách."""
    pass

class DecryptionIntegrityError(ABEError):
    """Lỗi khi dữ liệu hoặc bản mã đã bị thay đổi (tag AES-GCM không khớp)."""
    pass

class ABECoreGCM:
    """
    Triển khai ABE lai (Hybrid) an toàn.
    """
    def __init__(self, curve='SS512', pq_algo='Dilithium2'):
        self.group = PairingGroup(curve)
        self.abe = CPabe_BSW07(self.group)
        self.pq_algo = pq_algo
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def setup(self):
        return self.abe.setup()

    def keygen(self, pk, mk, user_attributes):
        """Tạo khóa người dùng dựa trên danh sách các thuộc tính đã được định dạng."""
        return self.abe.keygen(pk, mk, user_attributes)

    def encrypt(self, pk, plaintext, policy, user_id, timestamp, pqc_signer_object):
        """Mã hóa dữ liệu bằng ABE + AES-GCM, ký metadata chống misuse/replay."""
        sym_key = self.group.random(GT)
        abe_encrypted_key = self.abe.encrypt(pk, sym_key, policy)

        if abe_encrypted_key is None:
            raise ValueError("ABE encryption failed. Check policy syntax.")

        # Mã hóa dữ liệu bằng AES-GCM
        iv = get_random_bytes(12)
        aes_key = self._derive_key(sym_key)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(
            plaintext if isinstance(plaintext, bytes) else plaintext.encode('utf-8')
        )

        # Ký metadata bảo vệ context (chống misuse/replay)
        metadata = {
            'policy': policy,
            'user_id': user_id,
            'timestamp': timestamp,
            'abe_key_hex': objectToBytes(abe_encrypted_key, self.group).hex()
        }
        sig = pqc_signer_object.sign(json.dumps(metadata, sort_keys=True).encode())

        return {
            'iv': iv,
            'tag': tag,
            'data': ciphertext,
            'metadata': metadata,
            'sig': sig
        }

    def decrypt(self, pk, sk, ct, pq_verification_key):
        """Giải mã dữ liệu sau khi xác thực chữ ký, kiểm tra timestamp và policy."""
        # Bước 1: Xác thực chữ ký metadata
        metadata_bytes = json.dumps(ct['metadata'], sort_keys=True).encode()
        try:
            verifier = oqs.Signature(self.pq_algo)
            if not verifier.verify(metadata_bytes, ct['sig'], pq_verification_key):
                raise SignatureVerificationError("Xác thực chữ ký metadata thất bại.")
        except oqs.MechanismNotEnabledError:
            raise NotImplementedError(f"PQC '{self.pq_algo}' không được hỗ trợ.")

        # Bước 2: Kiểm tra timestamp hết hạn (ví dụ: 7 ngày)
        timestamp_str = ct['metadata']['timestamp']
        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Timestamp không hợp lệ: {timestamp_str}")
        
        if datetime.now(timezone.utc) > ts + timedelta(days=7):
            raise ValueError("Dữ liệu đã hết hạn: timestamp quá 7 ngày.")

        # Bước 3: Phục hồi abe_key và giải mã ABE
        abe_key_bytes = bytes.fromhex(ct['metadata']['abe_key_hex'])
        abe_key_obj = bytesToObject(abe_key_bytes, self.group)
        sym_key = self.abe.decrypt(pk, sk, abe_key_obj)
        if not sym_key:
            raise DecryptionPolicyError("Giải mã ABE thất bại: không thỏa mãn chính sách.")

        # Bước 4: Giải mã AES-GCM
        aes_key = self._derive_key(sym_key)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=ct['iv'])
        try:
            return cipher.decrypt_and_verify(ct['data'], ct['tag'])
        except ValueError:
            raise DecryptionIntegrityError("Giải mã AES-GCM thất bại: tag không hợp lệ.")

    def _derive_key(self, sym_key):
        """Sử dụng HKDF để dẫn xuất khóa AES một cách an toàn với SHA512."""
        return HKDF(str(sym_key).encode('utf-8'), 32, b"abe_symmetric_key_salt_v2", SHA512, 1)

    def serialize(self, obj):
        """Chuyển đổi đối tượng charm thành bytes."""
        return objectToBytes(obj, self.group)

    def deserialize(self, obj_bytes):
        """Chuyển đổi bytes thành đối tượng charm."""
        return bytesToObject(obj_bytes, self.group)

# === PHẦN 2: LỚP TƯƠNG THÍCH (ADAPTER) ===

class ABECompatWrapper:
    """
    Lớp tương thích (Adapter) để thay thế cho lớp ABECore cũ.
    """
    def __init__(self, curve='SS512', pq_algo='Dilithium2'):
        self.gcm_core = ABECoreGCM(curve, pq_algo)
        self.group = self.gcm_core.group
        
        try:
            self.pqc_signer = oqs.Signature(pq_algo)
            self.pq_pk = self.pqc_signer.generate_keypair()
            logging.info(f"Đã tạo cặp khóa PQC ('{pq_algo}') cho phiên làm việc này.")
        except Exception as e:
            logging.error(f"Lỗi không mong muốn trong quá trình khởi tạo OQS: {e}")
            raise

    def setup(self):
        return self.gcm_core.setup()

    def keygen(self, pk, mk, user_attributes):
        return self.gcm_core.keygen(pk, mk, user_attributes)

    def encrypt(self, pk, plaintext, policy, user_id):
        """
        Gói hàm encrypt của ABECoreGCM. Tự động tạo timestamp.
        """
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            logging.info(f"Đang mã hóa cho user '{user_id}' với chính sách: '{policy}'")
            return self.gcm_core.encrypt(pk, plaintext, policy, user_id, timestamp, self.pqc_signer)
        except Exception as e:
            logging.error(f"Mã hóa thất bại trong wrapper: {e}")
            traceback.print_exc()
            return None

    def decrypt(self, pk, sk, ct):
        """
        Gói hàm decrypt của ABECoreGCM.
        """
        try:
            return self.gcm_core.decrypt(pk, sk, ct, self.pq_pk)
        except ABEError as e:
            logging.warning(f"Giải mã thất bại trong wrapper: {e}")
            return None
        except Exception as e:
            logging.error(f"Lỗi không mong muốn trong quá trình giải mã: {e}")
            traceback.print_exc()
            return None
            
    # SỬA LỖI: Thêm lại các hàm tương thích đã bị thiếu
    def serialize_key(self, key):
        """Chuyển đổi đối tượng khóa thành chuỗi bytes đã mã hóa base64."""
        key_bytes = self.gcm_core.serialize(key)
        return base64.b64encode(key_bytes)

    def deserialize_key(self, b64_string):
        """Khôi phục đối tượng khóa từ chuỗi/bytes đã mã hóa base64."""
        key_bytes = base64.b64decode(b64_string)
        return self.gcm_core.deserialize(key_bytes)

    def save_public_key(self, pk, filename_prefix='keys', directory='.'):
        """Lưu khóa công khai vào file dưới dạng base64 text."""
        os.makedirs(directory, exist_ok=True)
        pk_b64_bytes = self.serialize_key(pk)
        with open(os.path.join(directory, f"{filename_prefix}_public.key"), 'w') as f:
            f.write(pk_b64_bytes.decode('utf-8'))
        logging.info(f"Đã lưu khóa công khai vào file '{filename_prefix}_public.key'")

    def load_public_key(self, filename='keys_public.key', directory='.'):
        """Tải khóa công khai từ file base64 text."""
        with open(os.path.join(directory, filename), 'r') as f:
            pk_b64_string = f.read().strip()
        return self.deserialize_key(pk_b64_string)

# === PHẦN 3: VÍ DỤ SỬ DỤNG ===
# (Phần này không thay đổi)
if __name__ == '__main__':
    
    print("--- Ví dụ sử dụng ABECompatWrapper (v20 - Final) ---")
    
    try:
        abe = ABECompatWrapper(pq_algo='Dilithium2')
        
        print("\n[1] Đang thiết lập hệ thống...")
        pk, mk = abe.setup()
        
        print("[2] Đang tạo khóa người dùng...")
        attrs = ['DOCTOR', 'HOSPITALA', 'D20250731']
        user_id_for_test = "user_123"
        user_sk = abe.keygen(pk, mk, attrs)
        print(f"    Thuộc tính: {attrs}")

        print("\n[3] Đang mã hóa tin nhắn...")
        message_str = "Hồ sơ bệnh nhân: Phân tích tim mạch mật."
        message = message_str.encode('utf-8')
        policy = f"({attrs[0]} and {attrs[1]}) and {attrs[2]}"
        
        print(f"    Tin nhắn: {message_str}")
        print(f"    Chính sách: {policy}")
        
        ciphertext = abe.encrypt(pk, message, policy, user_id_for_test)
        
        if ciphertext:
            print("    Mã hóa thành công. Đã tạo bản mã.")
        else:
            print("    Mã hóa thất bại.")
            exit()

        print("\n[4] Đang giải mã tin nhắn...")
        
        decrypted_message_bytes = abe.decrypt(pk, user_sk, ciphertext)
        
        if decrypted_message_bytes:
            decrypted_message_str = decrypted_message_bytes.decode('utf-8')
            print("    [THÀNH CÔNG] Giải mã thành công!")
            print(f"    Tin nhắn gốc:       {message_str}")
            print(f"    Tin nhắn giải mã:   {decrypted_message_str}")
            assert message_str == decrypted_message_str
        else:
            print("    [THẤT BẠI] Giải mã thất bại.")
            
    except SystemExit as e:
        print(f"\nChương trình đã dừng: {e}")
    except Exception as e:
        print(f"\nLỗi không xác định đã xảy ra: {e}")
        traceback.print_exc()