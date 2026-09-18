"""
Authentication Endpoints for NetSentinel.
Handles Registration, Login, and Current User profile retrieval.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.database.models import User
from backend.app.auth.jwt_handler import verify_password, get_password_hash, create_access_token
from backend.app.auth.deps import get_current_user
from backend.app.schemas.all_schemas import UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    hashed_pw = get_password_hash(req.password)
    # Role is ALWAYS forced to 'user' for public registrations.
    # An existing admin must promote an account to 'admin' through the admin portal.
    # Accepting req.role from an unauthenticated endpoint is a privilege escalation risk.
    new_user = User(
        name=req.name.strip(),
        email=req.email.lower().strip(),
        password_hash=hashed_pw,
        role="user"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)


    token = create_access_token({"sub": str(new_user.id), "role": new_user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": new_user
    }

@router.post("/login", response_model=TokenResponse)
def login(req: UserLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower().strip()).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = create_access_token({"sub": str(user.id), "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
