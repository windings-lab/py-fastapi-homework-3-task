from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    UserActivationResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetRequestResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.

    Creates a new user account with the provided email and password.
    The user is assigned to the default USER group and an activation token is created.
    """
    try:
        # Check if user already exists
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(stmt)
        existing_user = result.scalars().first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        # Get the default user group
        stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        result = await db.execute(stmt)
        user_group = result.scalars().first()

        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found."
            )

        # Create new user
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )

        db.add(user)
        await db.flush()  # Flush to get the user ID

        # Create activation token
        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()

        return UserRegistrationResponseSchema(
            id=cast(int, user.id),
            email=user.email
        )

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=UserActivationResponseSchema)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    """
    Activate a user account using an activation token.

    Validates the activation token and activates the user account.
    The activation token is deleted after successful activation.
    """
    # Get user and activation token
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    if not user.activation_token or user.activation_token.token != activation_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    # Check if token is expired
    expires_at = cast(datetime, user.activation_token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        # Delete expired token
        await db.execute(
            delete(ActivationTokenModel).where(ActivationTokenModel.id == user.activation_token.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    # Activate user and delete token
    user.is_active = True
    await db.execute(
        delete(ActivationTokenModel).where(ActivationTokenModel.id == user.activation_token.id)
    )
    await db.commit()

    return UserActivationResponseSchema(
        message="User account activated successfully."
    )


@router.post("/password-reset/request/", response_model=PasswordResetRequestResponseSchema)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    """
    Request a password reset token.

    If the user exists and is active, creates a new password reset token.
    Always returns the same success message to prevent information leakage.
    """
    # Get user
    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        # Delete any existing password reset tokens for this user
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )

        # Create new password reset token
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    return PasswordResetRequestResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=PasswordResetCompleteResponseSchema)
async def complete_password_reset(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    """
    Complete password reset using a valid reset token.

    Validates the reset token and updates the user's password.
    The reset token is deleted after successful password update.
    """
    try:
        # Get user
        stmt = select(UserModel).where(UserModel.email == reset_data.email)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Get password reset token
        stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == reset_data.token
        )
        result = await db.execute(stmt)
        reset_token = result.scalars().first()

        if not reset_token:
            # Delete any existing tokens for this user when invalid token is provided
            await db.execute(
                delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Check if token is expired
        expires_at = cast(datetime, reset_token.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            # Delete expired token
            await db.execute(
                delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == reset_token.id)
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Update password and delete token
        user.password = reset_data.password
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == reset_token.id)
        )
        await db.commit()

        return PasswordResetCompleteResponseSchema(
            message="Password reset successfully."
        )

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    """
    Authenticate user and return access and refresh tokens.

    Validates user credentials and generates JWT tokens upon successful authentication.
    The refresh token is stored in the database.
    """
    try:
        # Get user
        stmt = select(UserModel).where(UserModel.email == login_data.email)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        # Generate tokens
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        # Store refresh token in database
        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    """
    Refresh access token using a valid refresh token.

    Validates the refresh token and returns a new access token.
    """
    try:
        # Decode refresh token
        try:
            token_data = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

        user_id = token_data.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

        # Check if refresh token exists in database
        stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_data.refresh_token
        )
        result = await db.execute(stmt)
        refresh_token_record = result.scalars().first()

        if not refresh_token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        # Check if user exists
        stmt = select(UserModel).where(UserModel.id == user_id)
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        # Generate new access token
        access_token = jwt_manager.create_access_token({"user_id": user.id})

        return TokenRefreshResponseSchema(
            access_token=access_token
        )

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
