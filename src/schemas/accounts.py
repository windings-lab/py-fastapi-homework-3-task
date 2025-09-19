from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    """Schema for user registration request."""
    email: EmailStr
    password: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        return accounts_validators.validate_password_strength(v)


class UserRegistrationResponseSchema(BaseModel):
    """Schema for user registration response."""
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    """Schema for user account activation request."""
    email: EmailStr
    token: str


class UserActivationResponseSchema(BaseModel):
    """Schema for user account activation response."""
    message: str


class PasswordResetRequestSchema(BaseModel):
    """Schema for password reset token request."""
    email: EmailStr


class PasswordResetRequestResponseSchema(BaseModel):
    """Schema for password reset token request response."""
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    """Schema for password reset completion request."""
    email: EmailStr
    token: str
    password: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        return accounts_validators.validate_password_strength(v)


class PasswordResetCompleteResponseSchema(BaseModel):
    """Schema for password reset completion response."""
    message: str


class UserLoginRequestSchema(BaseModel):
    """Schema for user login request."""
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    """Schema for user login response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    """Schema for token refresh request."""
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    """Schema for token refresh response."""
    access_token: str
