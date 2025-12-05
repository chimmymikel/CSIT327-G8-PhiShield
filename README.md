# PhiShield - Phishing Detection System

A Django-based web application designed to detect and prevent phishing attacks by analyzing URLs and messages in real-time. PhiShield helps users identify suspicious links, scan emails, and monitor their security history through an intuitive dashboard.

## Features

- 🔍 **Enhanced URL Analysis**: Advanced phishing detection with multiple detection methods
  - Typosquatting detection (identifies domains similar to legitimate sites)
  - Domain reputation checks (SSL validation, subdomain analysis)
  - PhishTank API integration (verified phishing database)
  - Google Safe Browsing API integration (malware and phishing detection)
  - URL shortening service detection
  - Enhanced keyword and pattern matching
- 📧 **Message Scanning**: Analyze emails and messages for phishing content  
- 🛡️ **Real-time Protection**: Instant threat detection with risk scoring
- 📊 **Security Dashboard**: Monitor protection history
- 👥 **User Authentication**: Secure login and registration system

## Technology Stack

- **Programming Language**: Python
- **Web Framework**: Django 5.2.7
- **Frontend**: HTML, CSS, JavaScript, Bootstrap 5
- **Database**: Supabase (PostgreSQL)
- **Authentication**: Supabase Auth

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Supabase account and project

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/chimmymikel/PhiShield.git
cd PhiShield
```

2. Create a virtual environment:
```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# Create a .env file with your credentials
DATABASE_URL=postgresql://username:password@host:port/database
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_anon_key
SUPABASE_SECRET_KEY=your_supabase_secret_key

# Optional: Enhanced phishing detection API keys
# PhishTank API (free, optional - works without key but with rate limits)
PHISHTANK_API_KEY=your_phishtank_api_key_here

# Google Safe Browsing API (free tier available)
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
```

**Note on API Keys:**
- The system works without API keys, but with reduced detection accuracy
- All other detection methods (typosquatting, domain reputation, etc.) work without API keys
- To get API keys:
  - **PhishTank**: Register at https://www.phishtank.com/api_register.php (free)
  - **Google Safe Browsing**: Create credentials at https://console.cloud.google.com/apis/credentials (free tier available)

5. Run Django migrations:
```bash
python manage.py migrate
```

6. Run the Django development server:
```bash
python manage.py runserver
```

7. Open your browser and navigate to `http://127.0.0.1:8000/`

## Team Members

### Development Team
- **Michelle Marie P. Habon** (Lead Developer) - michellemarie.habon@cit.edu
- **Adrian V. Hernandez** (Backend Developer) - adrian.hernandez@cit.edu
- **Gave C. Hontiveros** (Frontend Developer) - gave.hontiveros@cit.edu

### Project Management Team
- **Jac Gary F. Cañete** (Product Owner) - jacgary.canete@cit.edu
- **Joseph Harry G. Butihen** (Business Analyst) - josephharry.butihen@cit.edu
- **Reenah Mae R. Campilanan** (Scrum Master) - reenahmae.campilanan@cit.edu

## Deployed Link
**Live Application**: https://csit327-g8-phishield-production.up.railway.app/

---

**PhiShield** - Protecting you from phishing threats, one click at a time.
