from marshmallow import Schema, fields, validate

class ChangePasswordSchema(Schema):
    old_password = fields.String(required=True)
    new_password = fields.String(required=True)

class LoginSchema(Schema):
    email    = fields.Email(required=True)
    password = fields.Str(required=True)

class EhrUploadSchema(Schema):
    policy = fields.Str(required=True, validate=validate.Length(min=3))

class EhrMetadataSchema(Schema):
    record_id = fields.Str(dump_only=True)
    filename  = fields.Str()
    uploaded_at = fields.DateTime(dump_only=True)

class ChangePasswordSchema(Schema):
    old_password = fields.String(required=True)
    new_password = fields.String(required=True)
