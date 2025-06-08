import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI     = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY              = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES    = timedelta(seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES")))

    SECRET_KEY                  = os.getenv("FLASK_SECRET_KEY")
    DEBUG                       = os.getenv("FLASK_DEBUG") == "True"

    AWS_REGION                  = os.getenv("AWS_REGION")
    S3_BUCKET_NAME              = os.getenv("S3_BUCKET_NAME")

    TA_BASE_URL                 = os.getenv("TA_BASE_URL")
    TA_API_TOKEN                = os.getenv("TA_API_TOKEN")
