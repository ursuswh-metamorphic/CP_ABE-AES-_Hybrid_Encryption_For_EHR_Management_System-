# '''
# import boto3, os, base64

# def store_secret(secret_name, secret_value):
#     client = boto3.client('secretsmanager', region_name=os.getenv('AWS_REGION'))
#     client.put_secret_value(SecretId=secret_name, SecretString=base64.b64encode(secret_value))

# def retrieve_secret(secret_name):
#     client = boto3.client('secretsmanager', region_name=os.getenv('AWS_REGION'))
#     response = client.get_secret_value(SecretId=secret_name)
#     return base64.b64decode(response['SecretString'])
# '''

# # utils/secrets_helper.py
# import os
# import base64
# import pickle

# SECRET_FILE = "secrets/mk.secret"

# def store_secret(secret_name, value_str):
#     with open(SECRET_FILE, 'w') as f:
#         f.write(value_str)

# def retrieve_secret(secret_name):
#     with open(SECRET_FILE, 'r') as f:
#         return f.read()

#25/6 fixing
# TA/utils/secrets_helper.py (Phiên bản dùng AWS Secrets Manager)
import boto3
import os
import base64 # Cần thiết nếu hàm retrieve_secret của bạn có decode

# Đảm bảo AWS_REGION được thiết lập trong môi trường của TA
AWS_REGION = os.getenv('AWS_REGION', 'ap-southeast-1') # Ví dụ: đặt một default nếu cần

def store_kms_encrypted_secret(secret_name, kms_encrypted_b64_string_value):
    """
    Lưu trữ một giá trị chuỗi (đã được KMS mã hóa và sau đó base64 encoded)
    vào AWS Secrets Manager.
    """
    client = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        client.put_secret_value(
            SecretId=secret_name,
            SecretString=kms_encrypted_b64_string_value  # Đây đã là string
        )
        print(f"Successfully stored KMS encrypted secret '{secret_name}' in Secrets Manager.")
    except Exception as e:
        print(f"Error storing KMS encrypted secret '{secret_name}' in Secrets Manager: {e}")
        raise

def retrieve_kms_encrypted_secret(secret_name):
    """
    Lấy một giá trị chuỗi (là ciphertext đã được base64 encoded)
    từ AWS Secrets Manager.
    Hàm này sẽ trả về chuỗi base64 của ciphertext.
    """
    client = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        if 'SecretString' in response:
            # 'SecretString' chứa chuỗi base64 của ciphertext mà chúng ta đã lưu.
            return response['SecretString']
        else:
            # Xử lý trường hợp nếu bạn vô tình lưu dưới dạng SecretBinary
            # Tuy nhiên, với chuỗi base64, SecretString là đúng.
            # Dòng này có thể không cần thiết nếu bạn luôn dùng SecretString.
            # return base64.b64encode(response['SecretBinary']).decode('utf-8')
            raise ValueError(f"Secret '{secret_name}' does not contain a SecretString.")
        print(f"Successfully retrieved KMS encrypted secret '{secret_name}' from Secrets Manager.")
    except Exception as e:
        print(f"Error retrieving KMS encrypted secret '{secret_name}' from Secrets Manager: {e}")
        raise