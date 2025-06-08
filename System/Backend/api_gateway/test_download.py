import os
import json
import base64
import requests
from abe_core import ABECore
from charm.core.engine.util import bytesToObject
import struct

def test_download_debug():
    """Debug version để tìm lỗi decrypt"""
    
    # 1. Tìm file encrypted gần nhất
    uploads_dir = "uploads"
    encrypted_files = [f for f in os.listdir(uploads_dir) if f.endswith('.enc')]
    latest_file = max(encrypted_files, key=lambda x: os.path.getctime(os.path.join(uploads_dir, x)))
    record_id = latest_file.replace('.enc', '')
    file_path = os.path.join(uploads_dir, latest_file)
    
    print(f"🔍 Testing file: {latest_file}")
    print(f"🔍 Record ID: {record_id}")
    
    try:
        # 2. Test với nhiều attributes khác nhau
        test_attributes = [
            ['doctor', 'cardiology'],
            ['doctor'],
            ['cardiology'],
            ['nurse', 'cardiology'],
            ['admin'],
        ]
        
        for attrs in test_attributes:
            print(f"\n🧪 Testing attributes: {attrs}")
            
            # Generate secret key
            keygen_response = requests.post(
                'https://localhost:5000/api/ehr/keygen',
                headers={'Content-Type': 'application/json'},
                json={'attributes': attrs},
                verify=False
            )
            
            if keygen_response.status_code != 200:
                print(f"❌ Keygen failed for {attrs}")
                continue
                
            secret_key_b64 = keygen_response.json()['secret_key']
            print(f"✅ Secret key generated for {attrs}")
            
            # Load encrypted file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Get public key
            pk_response = requests.get('https://localhost:5001/get_public_key', verify=False)
            pk_base64 = pk_response.json()['public_key']
            
            # Initialize ABE
            abe = ABECore()
            pk_bytes = base64.b64decode(pk_base64)
            pk = bytesToObject(pk_bytes, abe.group)
            sk = abe.deserialize_key(base64.b64decode(secret_key_b64))
            
            # Deserialize ciphertext
            try:
                # Read abe_key
                abe_key_len = struct.unpack('!I', encrypted_data[:4])[0]
                abe_key_bytes = encrypted_data[4:4+abe_key_len]
                abe_key = bytesToObject(abe_key_bytes, abe.group)
                
                # Read IV
                offset = 4 + abe_key_len
                iv_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
                iv = encrypted_data[offset+4:offset+4+iv_len]
                
                # Read encrypted data
                offset = offset + 4 + iv_len
                data_len = struct.unpack('!I', encrypted_data[offset:offset+4])[0]
                data = encrypted_data[offset+4:offset+4+data_len]
                
                ciphertext = {
                    'abe_key': abe_key,
                    'iv': iv,
                    'data': data
                }
                
                # DEBUG: In thông tin ciphertext
                print(f"🔍 Ciphertext info:")
                print(f"   - abe_key type: {type(ciphertext['abe_key'])}")
                print(f"   - iv length: {len(ciphertext['iv'])}")
                print(f"   - data length: {len(ciphertext['data'])}")
                
                # Try decrypt
                print(f"🔍 Attempting decrypt with attributes: {attrs}")
                plaintext = abe.decrypt(pk, sk, ciphertext)
                
                if plaintext is not None:
                    print(f"🎉 SUCCESS! Decrypted with attributes: {attrs}")
                    print(f"📄 Content: {plaintext[:100]}...")
                    
                    # Save result
                    output_file = f"decrypted_{record_id}_{'-'.join(attrs)}.txt"
                    with open(output_file, 'wb') as f:
                        f.write(plaintext)
                    print(f"📁 Saved to: {output_file}")
                    return  # Exit on success
                else:
                    print(f"❌ Failed with attributes: {attrs}")
                    
            except Exception as e:
                print(f"❌ Error with attributes {attrs}: {e}")
                continue
        
        print("\n❌ All attribute combinations failed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_download_debug()