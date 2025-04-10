from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials, firestore
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
import json
from uuid import uuid4
from google.cloud.firestore import FieldFilter
from google.cloud.firestore_v1 import FieldFilter
import os
import json
from dotenv import load_dotenv
import base64
from typing import Optional


# ✅ Load environment variables from .env file
load_dotenv()

# ✅ Read and Parse JSON safely
firebase_credentials_str = os.getenv("FIREBASE_CREDENTIALS")


if not firebase_credentials_str:
    raise ValueError("FIREBASE_CREDENTIALS environment variable is missing!")

try:
    # ✅ Decode from Base64 and load JSON
    firebase_credentials_json = base64.b64decode(firebase_credentials_str).decode()
    FIREBASE_CREDENTIALS = json.loads(firebase_credentials_json)
except Exception as e:
    raise ValueError(f"Failed to decode FIREBASE_CREDENTIALS: {e}")


# ✅ Initialize Firebase
cred = credentials.Certificate(FIREBASE_CREDENTIALS)
firebase_admin.initialize_app(cred)
db = firestore.client()

# 🔐 Load other environment variables
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 10080))


# 🔑 Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

PREDEFINED_PRIORITIES = ["Urgent", "High", "Medium", "Low"]
PREDEFINED_CATEGORIES = ["Personal", "Work"]


def initialize_global_data():
    """
    Ensure that predefined global priorities and categories exist in Firestore.
    """
    # 🔹 Add Predefined Priorities
    for priority in PREDEFINED_PRIORITIES:
        priority_ref = db.collection("priorities").document(priority)
        if not priority_ref.get().exists:
            priority_ref.set({"name": priority})

    # 🔹 Add Predefined Categories
    for category in PREDEFINED_CATEGORIES:
        category_ref = db.collection("categories").document(category)
        if not category_ref.get().exists:
            category_ref.set({"name": category})


# ✅ Run at startup
initialize_global_data()

# ✅ FastAPI App
app = FastAPI()

# ✅ User Model
class User(BaseModel):
    name: str
    email: str
    password: str

class UserProfile(BaseModel):
    name: str
    email: str

# ✅ Task Model
class Task(BaseModel):
    title: str
    dueDate: datetime
    isCompleted: bool = False
    priority: str
    category: str

class TaskUpdate(BaseModel):
    title: str = None
    dueDate: datetime = None
    isCompleted: bool = None
    priority: str = None
    category: str = None

# ✅ JWT Token Function
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ✅ Password Hashing Functions
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ✅ Get Current User
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# 🔥 Register User
@app.post("/register/")
def register_user(user: User):
    users_ref = db.collection("users").where(filter=FieldFilter("email", "==", user.email)).stream()

    for doc in users_ref:
        raise HTTPException(status_code=400, detail="User already exists")

    user_id = str(uuid4())
    hashed_password = hash_password(user.password)
    user_data = {"name": user.name, "email": user.email, "password": hashed_password}
    db.collection("users").document(user_id).set(user_data)

    return {"message": "User registered successfully", "user_id": user_id}

# 🔑 User Login
@app.post("/login/")
def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    user_email = form_data.username

    users_ref = db.collection("users").where(filter=FieldFilter("email", "==", user_email)).stream()
    user_doc = None
    for doc in users_ref:
        user_doc = doc.to_dict()
        break

    if not user_doc or not verify_password(form_data.password, user_doc["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    access_token = create_access_token(
        data={"sub": user_doc["email"]},
        expires_delta=timedelta(days=7)
    )

    return {"access_token": access_token, "token_type": "bearer", "expires_in": 7 * 24 * 60 * 60}  # Expiration in seconds

@app.get("/profile/", response_model=UserProfile)
def get_profile(user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where(filter=FieldFilter("email", "==", user_email)).stream()
    user_doc = None
    for doc in user_ref:
        user_doc = doc.to_dict()
        break

    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    # Exclude password from response
    user_profile = {
        "name": user_doc.get("name"),
        "email": user_doc.get("email"),
    }
    return user_profile


# 📌 Create Task with User-Specific Priority & Category
@app.post("/tasks/")
def create_task(task: Task, user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = None
    for doc in user_ref:
        user_id = doc.id
        break

    if not user_id:
        raise HTTPException(status_code=404, detail="User not found")

    # ✅ Ensure priority is predefined (users CANNOT create new priorities)
    if task.priority not in PREDEFINED_PRIORITIES:
        raise HTTPException(status_code=400, detail="Invalid priority. Please choose from predefined priorities.")

    # ✅ Store User-Specific Category (users CAN create new categories)
    if task.category not in PREDEFINED_CATEGORIES:
        db.collection("users").document(user_id).collection("categories").document(task.category).set({"name": task.category})


    # ✅ Create Task in User's Task Subcollection
    task_id = str(uuid4())
    task_data = {
        "title": task.title,
        "dueDate": task.dueDate,
        "isCompleted": task.isCompleted,
        "createdAt": datetime.utcnow(),
        "priority": task.priority,
        "category": task.category
    }

    db.collection("users").document(user_id).collection("tasks").document(task_id).set(task_data)
    return {"message": "Task created successfully", "task_id": task_id}


@app.get("/tasks/")
def get_all_tasks(
    category: Optional[str] = Query(None),
    user_email: str = Depends(get_current_user)
):
    """
    Retrieve all tasks for the authenticated user.
    Supports optional filtering by category.
    """
    # Get the user's Firestore document ID
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = next((doc.id for doc in user_ref), None)

    if not user_id:
        raise HTTPException(status_code=404, detail="User not found")

    # 🔍 Filter tasks by category if provided
    tasks_query = db.collection("users").document(user_id).collection("tasks")
    if category:
        tasks_query = tasks_query.where(filter=FieldFilter("category", "==", category))

    tasks_ref = tasks_query.stream()
    tasks = [{**task.to_dict(), "taskId": task.id} for task in tasks_ref]

    return {"tasks": tasks}


# 📌 Get Specific Task
@app.get("/tasks/{task_id}")
def get_task(task_id: str, user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = next((doc.id for doc in user_ref), None)

    task_ref = db.collection("users").document(user_id).collection("tasks").document(task_id)
    task = task_ref.get()
    if not task.exists:
        raise HTTPException(status_code=404, detail="Task not found")

    return task.to_dict()

# 📌 Update Task (Partial)
@app.patch("/tasks/{task_id}")
def update_task(task_id: str, task_update: TaskUpdate, user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = next((doc.id for doc in user_ref), None)

    task_ref = db.collection("users").document(user_id).collection("tasks").document(task_id)
    if not task_ref.get().exists:
        raise HTTPException(status_code=404, detail="Task not found")

    update_data = {k: v for k, v in task_update.dict().items() if v is not None}
    task_ref.update(update_data)
    return {"message": "Task updated successfully"}

# 📌 Delete Task
@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = next((doc.id for doc in user_ref), None)

    task_ref = db.collection("users").document(user_id).collection("tasks").document(task_id)
    if not task_ref.get().exists:
        raise HTTPException(status_code=404, detail="Task not found")

    task_ref.delete()
    return {"message": "Task deleted successfully"}


# 📌 Get All Priorities (Global)
@app.get("/priorities/all/")
def get_all_priorities():
    priorities = [doc.to_dict()["name"] for doc in db.collection("priorities").stream()]
    return {"priorities": priorities}

# 📌 Get All Categories (Global)
@app.get("/categories/all/")
def get_all_categories():
    categories = [doc.to_dict()["name"] for doc in db.collection("categories").stream()]
    return {"categories": categories}


# 📌 Get User-Specific Categories
@app.get("/users/categories/")
def get_user_categories(user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = None
    for doc in user_ref:
        user_id = doc.id
        break

    if not user_id:
        raise HTTPException(status_code=404, detail="User not found")

    categories = [doc.to_dict()["name"] for doc in db.collection("users").document(user_id).collection("categories").stream()]
    return {"categories": categories}


@app.delete("/users/categories/{category}")
def delete_user_category(category: str, user_email: str = Depends(get_current_user)):
    user_ref = db.collection("users").where("email", "==", user_email).stream()
    user_id = next((doc.id for doc in user_ref), None)

    category_ref = db.collection("users").document(user_id).collection("categories").document(category)
    if not category_ref.get().exists:
        raise HTTPException(status_code=404, detail="Category not found")

    category_ref.delete()
    return {"message": "Category deleted successfully"}