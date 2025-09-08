# ZeroHungry Animal Welfare Platform 🐾

## Overview
ZeroHungry Animal is a comprehensive platform for animal welfare that focuses on dog rescue, adoption, and donation tracking. The platform includes both user and admin interfaces to manage rescued dogs, track adoptions, and monitor donations.

![Platform Preview](git/image.png)

## Features
- 🐕 Dog Rescue Management
- 🏠 Adoption System
- 💰 Donation Tracking
- 📊 Admin Dashboard
- 📱 Responsive Design
- 📄 PDF Report Generation

## Tech Stack
- Python 3.10.11
- FastAPI
- SQLAlchemy
- HTML/CSS (TailwindCSS)
- JavaScript
- PostgreSQL

## Prerequisites
- Python 3.10.11 or higher
- PostgreSQL
- Virtual Environment (recommended)

## Installation

1. **Clone the repository**
```bash
git clone https://github.com/crazyscriptright/Zero_hunger.git
cd Zero_hunger
```

2. **Create and activate virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # For Linux/Mac
venv\Scripts\activate     # For Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Database Setup**
- Create a PostgreSQL database
- Restore the database using the provided dump file:
```bash
psql -U your_username -d your_database_name < signup.dump
```

5. **Environment Setup**
Create a `.env` file in the root directory with the following variables:
```env
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
STRIPE_PUBLISHABLE_KEY= your_pubshliable_key
SECRET_KEY=your_secret_key
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
```

## Running the Application

1. **Start the FastAPI server**
```bash
uvicorn main:app --reload
```

2. **Access the application**
- Main website: `http://127.0.0.1:8000`
- API documentation: `http://127.0.0.1:8000/docs`
- Alternative API docs: `http://127.0.0.1:8000/redoc`

## Project Structure
```
zerohungry-animal/
├── main.py              # FastAPI application
├── requirements.txt     # Project dependencies
├── .env                # Environment variables
├── static/             # Static files (images, css)
├── templates/          # HTML templates
└── __pycache__/        # Python cache files
```

## Demo
![Application Demo](git/msedge_5cq2EH6mAq.gif)

## Features in Detail

### Admin Panel
- Comprehensive dashboard for data visualization
- Dog rescue management
- Adoption tracking
- Donation monitoring
- PDF report generation

### User Features
- Browse available dogs
- Submit adoption requests
- Make donations
- Track donation usage

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- FastAPI framework
- TailwindCSS for styling
- Contributors and maintainers

## Support
For support, email support@zerohungry.com or raise an issue in the repository.