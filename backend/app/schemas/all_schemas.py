"""
Pydantic Schemas for API request validation and response serialization.
Pydantic v2 compliant with model_config dictionary.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

# ----------------- Auth Schemas -----------------

class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=100)
    role: Optional[str] = Field("user", pattern="^(user|admin)$")

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    created_at: datetime
    model_config = {"from_attributes": True, "protected_namespaces": ()}

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ----------------- Analysis Schemas -----------------

class AnalysisListItem(BaseModel):
    id: int
    filename: str
    file_size: int
    upload_time: datetime
    status: str
    predicted_class: str
    risk_score: int
    risk_level: str
    model_version: str
    query_count: int
    model_config = {"from_attributes": True, "protected_namespaces": ()}

class AnalysisResponse(BaseModel):
    id: int
    filename: str
    file_size: int
    upload_time: datetime
    status: str
    predicted_class: str
    risk_score: int
    risk_level: str
    rf_probability: float
    if_anomaly_score: float
    rule_score: float
    rule_flags: List[Dict[str, Any]]
    model_version: str
    query_count: int
    dns_features_summary: Dict[str, Any]
    queries_detail: List[Dict[str, Any]]
    risk_breakdown: Optional[Dict[str, Any]] = None
    model_config = {"from_attributes": True, "protected_namespaces": ()}

class DashboardStats(BaseModel):
    total_analyses: int
    attacks_detected: int
    benign_analyses: int
    anomalous_analyses: int
    average_risk_score: float
    recent_analyses: List[AnalysisListItem]
    model_config = {"from_attributes": True, "protected_namespaces": ()}

# ----------------- Admin & Model Schemas -----------------

class ModelVersionResponse(BaseModel):
    id: int
    version: str
    trained_at: datetime
    dataset_name: str
    sample_count: int
    feature_count: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    is_active: bool
    confusion_matrix: Optional[List[List[int]]] = None
    training_metadata: Optional[Dict[str, Any]] = None
    model_config = {"from_attributes": True, "protected_namespaces": ()}

class RetrainRequest(BaseModel):
    sample_size: Optional[int] = Field(150000, description="Number of training samples to use")
    n_estimators: Optional[int] = Field(100, ge=10, le=300)
    dataset_name: Optional[str] = "CIC-Bell-DNS-EXF-2021"

class AdminDashboardResponse(BaseModel):
    active_model: Optional[ModelVersionResponse]
    total_models: int
    total_analyses_systemwide: int
    total_users: int
    dataset_stats: Dict[str, Any]
    model_versions: List[ModelVersionResponse]
    model_config = {"from_attributes": True, "protected_namespaces": ()}
