"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import time
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path

from src.auth import (
    SESSION_COOKIE_NAME,
    User,
    authenticate_user,
    create_session,
    create_student_account,
    delete_session,
    get_student_account,
    get_user_for_session,
    normalize_email,
)

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


class StudentRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    name: str = Field(min_length=1, max_length=120)
    grade: str = Field(min_length=1, max_length=40)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def get_current_user(
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> User:
    user = get_user_for_session(session_token)
    if user is None:
        raise HTTPException(status_code=401, detail="Please log in to continue")
    return user


def _set_session_cookie(
    response: Response, request: Request, token: str, expires_at: int
) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max(0, expires_at - int(time.time())),
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )


def _public_user(user: User) -> dict[str, str | None]:
    return user.public_data()


@app.post("/auth/register", status_code=201)
def register_student(
    registration: StudentRegistration, request: Request, response: Response
):
    try:
        user = create_student_account(
            registration.email,
            registration.password,
            registration.name,
            registration.grade,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    token, expires_at = create_session(user)
    _set_session_cookie(response, request, token, expires_at)
    return _public_user(user)


@app.post("/auth/login")
def login(login_request: LoginRequest, request: Request, response: Response):
    user = authenticate_user(login_request.email, login_request.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token, expires_at = create_session(user)
    _set_session_cookie(response, request, token, expires_at)
    return _public_user(user)


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
):
    delete_session(session_token)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )
    return {"message": "Logged out"}


@app.get("/auth/me")
def current_user(user: Annotated[User, Depends(get_current_user)]):
    return _public_user(user)


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    user: Annotated[User, Depends(get_current_user)],
    email: str | None = None,
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    if user.role == "student":
        if email is not None:
            try:
                requested_email = normalize_email(email)
            except ValueError as error:
                raise HTTPException(status_code=400, detail=str(error)) from error
            if requested_email != user.email:
                raise HTTPException(
                    status_code=403,
                    detail="Students can only sign themselves up",
                )
        student_email = user.email
    elif user.role == "admin":
        if email is None:
            raise HTTPException(
                status_code=400,
                detail="Administrators must provide the student's email",
            )
        try:
            student_email = normalize_email(email)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        if get_student_account(student_email) is None:
            raise HTTPException(status_code=404, detail="Student account not found")
    else:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if student_email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(student_email)
    return {"message": f"Signed up {student_email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    user: Annotated[User, Depends(get_current_user)],
    email: str | None = None,
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    if user.role == "student":
        if email is not None:
            try:
                requested_email = normalize_email(email)
            except ValueError as error:
                raise HTTPException(status_code=400, detail=str(error)) from error
            if requested_email != user.email:
                raise HTTPException(
                    status_code=403,
                    detail="Students can only unregister themselves",
                )
        student_email = user.email
    elif user.role == "admin":
        if email is None:
            raise HTTPException(
                status_code=400,
                detail="Administrators must provide the student's email",
            )
        try:
            student_email = normalize_email(email)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
    else:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if student_email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(student_email)
    return {"message": f"Unregistered {student_email} from {activity_name}"}
