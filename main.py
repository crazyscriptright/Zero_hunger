from datetime import date  # Add this import
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String,Text,DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Float
from fastapi import FastAPI, BackgroundTasks, Depends
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import os
import stripe
from dotenv import load_dotenv
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

# from models import Feedback
from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, func
# from database import engine, Base
# from database import get_db
from sqlalchemy import Column, Integer, String, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Numeric, Text, TIMESTAMP, func



#admin
from datetime import datetime, timedelta

#Dogs
import base64
from sqlalchemy import Column, Integer, String, Text, Date, DateTime, Boolean, TIMESTAMP, func
from typing import Optional  # ✅ Ensure this import is present

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")



app = FastAPI()
templates = Jinja2Templates(directory="templates/Admin") # Corrected here!

# Set up the templates directory



# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust to specific origins if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
  # Replace with your credentials
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()



class User(Base):
    __tablename__ = "users"


    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    phone_number = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    dob = Column(Date, nullable=False) 


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, default=func.now())

class Donation(Base):
    __tablename__ = "donations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    donation_time = Column(TIMESTAMP, server_default=func.now())

class DonationSpending(Base):
    __tablename__ = "donation_spending"
    id = Column(Integer, primary_key=True, index=True)
    spending_amount = Column(Integer, nullable=False)
    remaining_balance = Column(Integer, nullable=False)
    purpose = Column(String, nullable=False)
    spending_time = Column(DateTime, default=func.now())  # Add this line

class Dog(Base):
    __tablename__ = "dogs"
    id = Column(Integer, primary_key=True, index=True)
    name_of_dog = Column(String(100), nullable=False)
    owner = Column(String(100), default=None)
    owner_full_name = Column(String(255), default=None)
    phone_number = Column(String(20), default=None)
    address = Column(Text, default=None)
    adopted_date = Column(Date, default=func.current_date())
    agreement_accepted = Column(Boolean, default=False)
    image = Column(String, default=None)
    sex = Column(String(100))
    created_date = Column(TIMESTAMP, server_default=func.now())
    modified_date = Column(TIMESTAMP, server_default=func.now())
    age = Column(Integer, default=None)
    status = Column(String(20), default="Available", nullable=False)  # Ensure the column is defined and not nullable

class DogRescue(Base):
    __tablename__ = "dog_rescue"
    id = Column(Integer, primary_key=True, index=True)
    rescue_location = Column(String, nullable=False)
    condition_of_dog = Column(Text, nullable=False)
    dog_image_base64 = Column(Text, default=None)
    rescue_status = Column(String, default="Pending")
    contact_info = Column(String, nullable=False)
    additional_notes = Column(Text, default=None)
    created_at = Column(TIMESTAMP, server_default=func.now())

# Create Tables
Base.metadata.create_all(bind=engine)

#create a feedback table
# Base.metadata.create_all(bind=engine)

# FastAPI App
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    phone_number: str
    password: str
    dob: date

class UserLogin(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    dob: date
    new_password: str

class FeedbackCreate(BaseModel):
    name: str
    email: str
    message: str

# Pydantic Models for Validation
class DonationCreate(BaseModel):
    donor_name: str
    email: str
    amount: int

class SpendingCreate(BaseModel):
    spending_amount: int
    purpose: str

class DogRequest(BaseModel):
    name_of_dog: str
    owner: str = None
    image: str = None  # Base64 format
    sex: str
    age: int

class DogRescueRequest(BaseModel):
    rescue_location: str
    condition_of_dog: str
    dog_image_base64: str = None
    rescue_status: str = "Pending"
    contact_info: str
    additional_notes: str = None

class StatusUpdateRequest(BaseModel):
    status: str

class DogRequest(BaseModel):
    name_of_dog: Optional[str] = None
    sex: Optional[str] = None
    age: Optional[int] = None
    image: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    username: str
    current_password: str
    new_password: str
    confirm_password: str

# Dependency to Get Database Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency to Check if User is Admin
def is_admin(request: Request):
    username = request.cookies.get("username")
    print(f"Debug: Username from cookies: {username}")  # Debug print statement
    if not username or username.lower() != "admin":
        raise HTTPException(status_code=403, detail=f"Access denied. Admins only. {username}")


# feedback
@app.post("/feedback")
def create_feedback(feedback: FeedbackCreate, db: Session = Depends(get_db)):
    db_feedback = Feedback(
        name=feedback.name,
        email=feedback.email,
        message=feedback.message
    )
    db.add(db_feedback)
    db.commit()
    db.refresh(db_feedback)
    return {"message": "Feedback submitted successfully", "id": db_feedback.id}

# Signup Endpoint


ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

@app.post("/login")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    # Check if the provided credentials match the hardcoded admin credentials
    if user.username == ADMIN_USERNAME and user.password == ADMIN_PASSWORD:
        return {"message": "Welcome Admin!", "redirect": "/admin"}

    # Fetch the User by Username
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    # Verify the Password
    if not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password.")

    return {"message": f"Welcome {db_user.username} to the main page!", "redirect": "/"}

@app.post("/signup")
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the user already exists
    if user.username.lower() == ADMIN_USERNAME.lower():
        raise HTTPException(status_code=400, detail="Username not allowed.")
    existing_user = db.query(User).filter((User.username == user.username) | (User.email == user.email) ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists. Please log in.")
    existing_user = db.query(User).filter((User.phone_number == user.phone_number)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Phone number already exists. Please log in.")

    # Hash the password and create a new user
    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        phone_number=user.phone_number,
        password=hashed_password,
        dob=user.dob
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"message": "User created successfully!"}


@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Find the user by email
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify the date of birth
    if user.dob != request.dob:
        raise HTTPException(status_code=400, detail="Invalid date of birth")
    
    # Update the user's password
    hashed_password = pwd_context.hash(request.new_password)
    user.password = hashed_password
    db.commit()
    
    return {"message": "Password updated successfully"}

@app.post("/change-password")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    # Fetch the user by username
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify the current password
    if not pwd_context.verify(request.current_password, user.password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Check if new password and confirm password match
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match")

    # Hash the new password and update the user's password
    hashed_password = pwd_context.hash(request.new_password)
    user.password = hashed_password
    db.commit()

    return {"message": "Password changed successfully"}

@app.get("/users/count")
def get_user_count(db: Session = Depends(get_db)):
    """Returns the total number of registered users."""
    user_count = db.query(User).count()
    return {"user_count": user_count}

# @app.get("/users")
# def get_users(db: Session = Depends(get_db)):
#     """Returns a list of all registered users."""
#     users = db.query(User).all()
#     return [{"id": user.id, "name": user.name, "email": user.email, "created_at": user.created_at} for user in users]


@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    """Fetch all registered users with details."""
    users = db.query(User).all()
    return [
        {
            "id": user.id,
            "username": user.username,  # Correct field name
            "email": user.email,
            "phone_number": user.phone_number  # Ensure this matches your database column
        }
        for user in users
    ]

@app.get("/donations/count")
def get_donation_count(db: Session = Depends(get_db)):
    """Returns the total count and sum of all donations."""
    total_amount = db.query(func.sum(Donation.amount)).scalar() or 0
    return {"total_amount": total_amount}

@app.get("/donations")
def get_donations(db: Session = Depends(get_db)):
    """Returns a list of all donations with donor names and amounts."""
    donations = db.query(Donation).all()
    return [{"id": donation.id, "donor_name": donation.donor_name, "amount": donation.amount, "date": donation.date} for donation in donations]


@app.get("/feedback/count")
def get_feedback_count(db: Session = Depends(get_db)):
    count = db.query(func.count(Feedback.id)).scalar()  # Count the number of feedbacks
    return JSONResponse(content={"count": count})


# Setting up templates and static files
templates = Jinja2Templates(directory="templates")

# Optional: Serve static files (like CSS, JS, images) if needed
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/signup", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot-password.html", {"request": request})

@app.get("/", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("updatedindex.html", {"request": request})

@app.get("/contact", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("contact.html", {"request": request})

@app.get("/dogshelter", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("dogshelter.html", {"request": request})

@app.get("/medicalcare", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("medicalcare.html", {"request": request})

@app.get("/volunteer", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("volunteer.html", {"request": request})

# @app.get("/fooddistrubution", response_class=HTMLResponse)
# async def dog_shelter_page(request: Request):
#     return templates.TemplateResponse("fooddistrubution.html", {"request": request})

@app.get("/adoption", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("Adoption.html",{"request":request})

@app.get("/donate/cancel", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("cancel.html", {"request": request})

@app.get("/donate/success", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("success.html", {"request": request})

@app.get("/about", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("about.html", {"request": request})

@app.get("/change-password", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("change-password.html", {"request": request})

@app.get("/gallery", response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("gallery.html", {"request": request})

# Admin Page Route

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

@app.get("/Admin/AdminHome",response_class=HTMLResponse)
async def dog_shelter_page(request: Request):
    return templates.TemplateResponse("/Admin/AdminHome.html", {"request": request})

@app.get("/all-dogs", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("all-dogs.html", {"request": request})

@app.get("/Admin/all-dogs", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("/Admin/AdViewalldogs.html", {"request": request})

@app.get("/Admin/all-resue", response_class=HTMLResponse)
async def cridet_page(request: Request):
    return templates.TemplateResponse("AdResueTable.html", {"request": request})

@app.get("/rescues/pending/count", response_class=JSONResponse)
def get_pending_rescue_count(db: Session = Depends(get_db)):
    """Returns the count of pending rescues."""
    pending_count = db.query(func.count(DogRescue.id)).filter(DogRescue.rescue_status == "Pending").scalar()
    return {"pending_rescues": pending_count}


@app.get("/rescues/Escalated/count", response_class=JSONResponse)
def get_pending_rescue_count(db: Session = Depends(get_db)):
    """Returns the count of pending rescues."""
    pending_count = db.query(func.count(DogRescue.id)).filter(DogRescue.rescue_status == "Escalated").scalar()
    return {"pending_rescues": pending_count}




# extra

@app.get("/users/", response_model=list[UserCreate])
async def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users



# Setup for serving templates
templates = Jinja2Templates(directory="templates")

# Serve static files (if needed, like CSS or JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Route for displaying the donation form (GET request)
@app.get("/donate", response_class=HTMLResponse)
async def donate_page(request: Request):
    return templates.TemplateResponse("donate.html", {"request": request})

# Route for processing the donation form (POST request)
# Define a Pydantic model for the donation request
class DonationRequest(BaseModel):
    name: str
    email: str
    amount: float

from fastapi import HTTPException, Depends, Request
from fastapi.responses import JSONResponse
import stripe
from sqlalchemy.orm import Session

@app.post("/create-checkout-session/")
async def create_checkout_session(
    donation: DonationRequest, 
    request: Request,  # Add request object to access headers
    db: Session = Depends(get_db)
):
    try:
        # Get the referrer URL from the request headers
        referrer_url = request.headers.get("Referer")
        if not referrer_url:
            raise HTTPException(status_code=400, detail="Referer header is missing")

        # Convert amount to cents (Stripe requires smallest currency unit)
        amount_in_cents = int(donation.amount * 100)

        # Create Stripe Checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[
                {
                    "price_data": {
                        "currency": "inr",
                        "product_data": {"name": "Donation"},
                        "unit_amount": amount_in_cents,
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            success_url=f"{referrer_url}/success",  # Redirect back to the same URL + /success
            cancel_url=f"{referrer_url}/cancel",  # Redirect back to the same URL + /cancel
        )

        # Save donation details to the database
        db_donation = Donation(
            name=donation.name,
            email=donation.email,
            amount=donation.amount
        )
        db.add(db_donation)
        db.commit()
        db.refresh(db_donation)

        # Return session URL
        return JSONResponse(content={"url": session.url})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

        
@app.post("/webhook/")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    endpoint_secret = "your_webhook_secret"

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except stripe.error.SignatureVerificationError as e:
        raise HTTPException(status_code=400, detail="Webhook signature verification failed.")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        name = session["metadata"]["name"]
        email = session["metadata"]["email"]
        amount = session["amount_total"] / 100  # Convert paisa to ₹

        # Store in database (you already have this)
        db_donation = Donation(name=name, email=email, amount=amount)
        db = SessionLocal()
        db.add(db_donation)
        db.commit()
        db.refresh(db_donation)

        # Send email confirmation (if configured)
        # background_tasks.add_task(send_email, name, email, amount)

    return {"message": "Webhook received"}

    ####ADMIN PAGE details are below################

@app.get("/viewDonations", response_class=JSONResponse)
def get_donations(db: Session = Depends(get_db)):
    """Fetches all donation records."""
    donations = db.query(Donation).order_by(Donation.donation_time.desc()).all()
    return {
        "donations": [
            {
                "id": d.id,
                "name": d.name,
                "email": d.email,
                "amount": d.amount,
                "date": d.donation_time.strftime("%Y-%m-%d %H:%M:%S"),  # Format the date
            }
            for d in donations
        ]
    }

@app.get("/donations/summary", response_class=JSONResponse)
def get_donation_summary(db: Session = Depends(get_db)):
    """Fetch donation summary statistics."""
    total_donations = db.query(func.count(Donation.id)).scalar() or 0
    total_amount = db.query(func.sum(Donation.amount)).scalar() or 0
    avg_donation = db.query(func.avg(Donation.amount)).scalar() or 0

    # Fetch top 5 donors by amount
    top_donors = (
        db.query(Donation.name, func.sum(Donation.amount).label("total_amount"))
        .group_by(Donation.name)
        .order_by(func.sum(Donation.amount).desc())
        .limit(5)
        .all()
    )

    return {
        "total_donations": total_donations,
        "total_amount": total_amount,
        "avg_donation": round(avg_donation, 2),
        "top_donors": [{"name": donor[0], "amount": donor[1]} for donor in top_donors],
    }

@app.get("/viewFeedback", response_class=JSONResponse)
def get_feedback(db: Session = Depends(get_db)):
    """Fetch all feedback records."""
    feedbacks = db.query(Feedback).order_by(Feedback.id).all()
    return {"feedbacks": [dict(id=f.id, name=f.name, email=f.email, message=f.message, created_at=f.created_at) for f in feedbacks]}

@app.get("/viewRegistrations", response_class=JSONResponse)
def get_registrations(db: Session = Depends(get_db)):
    """Fetch registration counts for the past 15 days."""
    today = datetime.utcnow()
    start_date = today - timedelta(days=15)
    
    # Query to get registration counts per day
    registration_data = (
        db.query(func.date(User.created_at), func.count(User.id))
        .filter(User.created_at >= start_date)
        .group_by(func.date(User.created_at))
        .order_by(func.date(User.created_at))
        .all()
    )

    # Convert data to dictionary format
    registrations = [{"date": str(date), "count": count} for date, count in registration_data]

    # Calculate average growth rate
    total_days = len(registrations)
    if total_days > 1:
        first_day_count = registrations[0]["count"]
        last_day_count = registrations[-1]["count"]
        avg_growth_rate = ((last_day_count - first_day_count) / total_days) * 100
    else:
        avg_growth_rate = 0

    return {"registrations": registrations, "avg_growth_rate": round(avg_growth_rate, 2)}

# Function to calculate total donations
def get_total_donations(db):
    total_donations = db.query(func.sum(Donation.amount)).scalar()
    return total_donations if total_donations else 0

# Function to calculate total spending
def get_total_spent(db):
    total_spent = db.query(func.sum(DonationSpending.spending_amount)).scalar()
    return total_spent if total_spent else 0

# Function to calculate available balance
def get_available_balance(db):
    total_donations = get_total_donations(db)
    total_spent = get_total_spent(db)
    return total_donations - total_spent

@app.get("/total_donations")
def read_total_donations(db: Session = Depends(get_db)):
    total_donations = get_total_donations(db)
    return {"total_donations": total_donations}

# Endpoint to get total spending
@app.get("/total_spent")
def read_total_spent(db: Session = Depends(get_db)):
    total_spent = get_total_spent(db)
    return {"total_spent": total_spent}

# Endpoint to get available balance
@app.get("/available_balance")
def read_available_balance(db: Session = Depends(get_db)):
    available_balance = get_available_balance(db)
    return {"available_balance": available_balance}


# 3️ Spend money (Admin Only)
@app.post("/donations/spend")
def add_spending(spending: SpendingCreate, db: Session = Depends(get_db)):
    # Calculate total donations received
    total_donations = db.query(func.sum(Donation.amount)).scalar() or 0
    # Calculate total spending so far
    total_spent = db.query(func.sum(DonationSpending.spending_amount)).scalar() or 0
    # Calculate remaining balance
    remaining_balance = total_donations - total_spent
    
    if spending.spending_amount > remaining_balance:
        raise HTTPException(status_code=400, detail="Spending amount exceeds available balance")
    
    # Insert new spending record
    new_spending = DonationSpending(
        spending_amount=spending.spending_amount,
        remaining_balance=remaining_balance - spending.spending_amount,
        purpose=spending.purpose
    )
    db.add(new_spending)
    db.commit()
    db.refresh(new_spending)
    return {"message": "Spending record added successfully", "remaining_balance": new_spending.remaining_balance}


# 4️⃣ Fetch all spending records
@app.get("/donations/spending", response_class=JSONResponse)
def get_spending_records(db: Session = Depends(get_db)):
    """Retrieve all spending records."""
    spending_records = db.query(DonationSpending).order_by(DonationSpending.spending_time.desc()).all()
    return {
        "spendings": [{"id": s.id, "amount": s.spending_amount, "purpose": s.purpose, "time": s.spending_time} for s in spending_records]
    }


###################Dogs#########33


@app.post("/dogs/add", response_class=JSONResponse)
def add_dog(dog: DogRequest, db: Session = Depends(get_db)):
    new_dog = Dog(
        name_of_dog=dog.name_of_dog,
        sex=dog.sex,
        image=dog.image,  # Base64 Image
        age=dog.age  # ✅ You missed adding age here
    )
    db.add(new_dog)
    db.commit()
    return {"message": "Dog added successfully"}



@app.get("/dogs", response_class=JSONResponse)
def get_all_dogs(db: Session = Depends(get_db)):
    """Fetch all dog records."""
    dogs = (
        db.query(Dog)
        .filter(Dog.status == "Available")  # Filter where owner is NULL
        .all()
    )
    return {
        "dogs": [
            {
                "id": dog.id,
                "name_of_dog": dog.name_of_dog,  # Correct field name
                "sex": dog.sex,
                "image": dog.image,  # Already in Base64 format
                "age": dog.age # Only date part
            }
            for dog in dogs
        ]
    }



@app.get("/dogs-10", response_class=JSONResponse)
def get_all_dogs(db: Session = Depends(get_db)):
    """Fetch the last 10 dog records where owner is NULL."""
    dogs = (
        db.query(Dog)
        .filter(Dog.status == "Available")  # Filter where owner is NULL
        .order_by(Dog.created_date.desc())  # Sort by latest created date
        .limit(10)  # Fetch only the last 10 records
        .all()
    )

    return {
        "dogs": [
            {
                "id": dog.id,
                "name_of_dog": dog.name_of_dog,
                "sex": dog.sex,
                "image": dog.image,  # Already in Base64 format
                "age": dog.age
            }
            for dog in dogs
        ]
    }

# Route to Fetch All Dogs
@app.get("/dogs")
def get_all_dogs(db: Session = Depends(get_db)):
    dogs = db.query(Dog).filter(Dog.owner == None).all()
    return {"dogs": dogs}

# Adopt Dog Route
@app.post("/adopt-dog/{dog_id}")
def adopt_dog(dog_id: int, email: str, owner_full_name: str, phone_number: str, address: str, agreement_accepted: bool, db: Session = Depends(get_db)):
    dog = db.query(Dog).filter(Dog.id == dog_id).first()
    
    if not dog:
        raise HTTPException(status_code=404, detail="Dog not found")
    
    if dog.owner:
        raise HTTPException(status_code=400, detail="Dog already adopted")
    
    dog.owner = email
    dog.owner_full_name = owner_full_name
    dog.phone_number = phone_number
    dog.address = address
    dog.agreement_accepted = agreement_accepted
    dog.adopted_date = func.current_date()
    dog.status = "Pending"
    db.commit()  # Commit the changes to the database
    return {"message": "Request forwarded Kindly visit Office"}

from fastapi.responses import JSONResponse

@app.get("/admin/dogs", response_class=JSONResponse)
def get_all_dogs(db: Session = Depends(get_db)):
    """Fetch all dog records from the database and return as JSON."""
    dogs = db.query(Dog).all()

    return {
        "dogs": [
            {
                "id": dog.id,
                "name_of_dog": dog.name_of_dog,
                "sex": dog.sex,
                "age": dog.age,
                "owner": dog.owner,
                "created_date": dog.created_date,
                "adopted_date": dog.adopted_date,  # Added adopted_date column
            }
            for dog in dogs
        ]
    }

@app.put("/dogs/update/{dog_id}", response_class=JSONResponse)
def update_dog(dog_id: int, dog: DogRequest, db: Session = Depends(get_db)):
    existing_dog = db.query(Dog).filter(Dog.id == dog_id).first()
    if not existing_dog:
        raise HTTPException(status_code=404, detail="Dog not found")

    if dog.name_of_dog is not None:
        existing_dog.name_of_dog = dog.name_of_dog
    if dog.sex is not None:
        existing_dog.sex = dog.sex
    if dog.age is not None:
        existing_dog.age = dog.age
    if dog.image is not None:
        existing_dog.image = dog.image

    db.commit()
    return {"message": "Dog details updated successfully"}


# Delete Dog
@app.delete("/dogs/delete/{dog_id}", response_class=JSONResponse)
def delete_dog(dog_id: int, db: Session = Depends(get_db)):
    existing_dog = db.query(Dog).filter(Dog.id == dog_id).first()
    if not existing_dog:
        raise HTTPException(status_code=404, detail="Dog not found")

    db.delete(existing_dog)
    db.commit()
    return {"message": "Dog deleted successfully"}


@app.post("/admin/adoption-requests/update-status/{dog_id}", response_class=JSONResponse)
def update_dog_status(dog_id: int, request: StatusUpdateRequest, db: Session = Depends(get_db)):
    """
    Update the status of a dog (e.g., Approve or Reject) by the admin.
    If the status is set to 'Available', reset adoption details to null.
    """
    valid_statuses = ["Available", "Pending", "Adopted", "Rejected"]  # Define valid statuses
    if request.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status value")

    # Fetch the dog record by ID
    dog = db.query(Dog).filter(Dog.id == dog_id).first()
    if not dog:
        raise HTTPException(status_code=404, detail="Dog not found")

    # Update the status for 'Adopted'
    if request.status == "Adopted":
        dog.status = request.status
        dog.adopted_date = func.current_date()

    # If the status is 'Available', reset adoption details
    elif request.status == "Available":
        dog.status = request.status
        dog.agreement_accepted = False
        dog.owner = None
        dog.owner_full_name = None
        dog.phone_number = None
        dog.address = None
        dog.adopted_date = None

    # Commit the changes explicitly
    db.commit()

    # Refresh the dog instance to ensure all changes are applied
    db.refresh(dog)  

    return {"message": f"Dog status updated to '{request.status}' successfully"}


@app.get("/admin/adoption-requests", response_class=JSONResponse)
def get_adoption_requests(db: Session = Depends(get_db)):
    """
    Fetch all adoption requests where the status is 'Pending'.
    """
    adoption_requests = (
        db.query(Dog)
        .filter(Dog.status == "Pending")
        .all()
    )
    return {
        "adoption_requests": [
            {
                "id": dog.id,
                "name_of_dog": dog.name_of_dog,
                "owner_full_name": dog.owner_full_name,
                "phone_number": dog.phone_number,
                "address": dog.address,
                "status": dog.status,
                "created_date": dog.created_date,
            }
            for dog in adoption_requests
        ]
    }

##################Rescue#################

@app.post("/add-rescue")
def add_dog_rescue(rescue: DogRescueRequest, db: Session = Depends(get_db)):
    new_rescue = DogRescue(**rescue.dict())
    db.add(new_rescue)
    db.commit()
    return {"message": "Rescue details added successfully!"}


# Endpoint to fetch all rescues
@app.get("/rescues", response_class=JSONResponse)
def get_all_rescues(db: Session = Depends(get_db)):
    # Fetch all rescues from the database
    rescues = db.query(DogRescue).all()
    
    # Return all rescues as a JSON response
    return {
        "rescues": [
            {
                "id": rescue.id,
                "rescue_location": rescue.rescue_location,
                "condition_of_dog": rescue.condition_of_dog,
                "rescue_status": rescue.rescue_status,
                "created_at": rescue.created_at,
                "contact_info": rescue.contact_info,
                "additional_notes": rescue.additional_notes,
                "dog_image_base64": rescue.dog_image_base64
            }
            for rescue in rescues
        ]
    }

@app.put("/update-status/{id}", response_class=JSONResponse)
def update_status(id: int, request: StatusUpdateRequest, db: Session = Depends(get_db)):
    rescue = db.query(DogRescue).filter(DogRescue.id == id).first()
    if not rescue:
        raise HTTPException(status_code=404, detail="Rescue not found")

    rescue.rescue_status = request.status
    db.commit()
    return {"message": "Status updated successfully"}


@app.get("/resues/image/{id}", response_class=JSONResponse)
def get_image(id: int, db: Session = Depends(get_db)):
    rescue = db.query(DogRescue).filter(DogRescue.id == id).first()
    if not rescue or not rescue.dog_image_base64:
        return {"message": "Image not found"}, 404

    return {"image": rescue.dog_image_base64}