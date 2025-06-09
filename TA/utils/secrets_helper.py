'''
import boto3, os, base64

def store_secret(secret_name, secret_value):
    client = boto3.client('secretsmanager', region_name=os.getenv('AWS_REGION'))
    client.put_secret_value(SecretId=secret_name, SecretString=base64.b64encode(secret_value))

def retrieve_secret(secret_name):
    client = boto3.client('secretsmanager', region_name=os.getenv('AWS_REGION'))
    response = client.get_secret_value(SecretId=secret_name)
    return base64.b64decode(response['SecretString'])
'''

# utils/secrets_helper.py
import os
import base64
import pickle

SECRET_FILE = "secrets/mk.secret"

def store_secret(secret_name, value_str):
    with open(SECRET_FILE, 'w') as f:
        f.write(value_str)

def retrieve_secret(secret_name):
    with open(SECRET_FILE, 'r') as f:
        return f.read()
