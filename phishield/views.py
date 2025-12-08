from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.utils import timezone
from django.contrib.auth.models import User
from .models import SuspiciousLink, SuspiciousMessage, UserProfile
from .forms import LinkForm, MessageForm, RegisterForm
from .utils import analyze_url, analyze_message
from django.contrib import messages
from django.core.mail import send_mail  # ✅ Added for email
from django.conf import settings        # ✅ Added to access email settings
import random
import logging
import os
from datetime import datetime

# ✅ Initialize logger
logger = logging.getLogger('phishield')

TIPS = [
    "Always verify the sender's email address before clicking links.",
    "Check for HTTPS and a padlock icon in your browser's address bar.",
    "Be wary of urgent messages asking you to act immediately.",
    "Never share passwords or sensitive info via email or message.",
    "Hover over links to preview the actual URL before clicking.",
    "Be suspicious of shortened URLs from unknown sources.",
    "Look for spelling errors in domain names.",
    "Enable two-factor authentication on all important accounts.",
]


def save_analysis_result(user, check_type, content, risk_level, flags):
    """Save analysis results to a local log file"""
    log_dir = "analysis_logs"
    
    # Create logs directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create log file with today's date
    today = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"analysis_results_{today}.log")
    
    # Format the log entry
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] | User: {user.username} | Type: {check_type} | Risk: {risk_level}\n"
    log_entry += f"Content: {content}\n"
    log_entry += f"Flags: {flags}\n"
    log_entry += "-" * 80 + "\n"
    
    # Write to log file
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    return log_file


def index(request):
    """Homepage - redirect based on authentication"""
    if request.user.is_authenticated:
        return redirect('phishield:dashboard')
    return render(request, 'phishield/index.html')


def register(request):
    """User registration view - AUTO VERIFIED & IMMEDIATE ACCESS"""
    if request.user.is_authenticated:
        return redirect('phishield:dashboard')

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            # ✅ FIXED: Use get_or_create to handle existing profiles
            profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={
                    'email_verified': True,  # ✅ Auto-verify new profiles
                    'role': 'employee'
                }
            )
            
            # ✅ If profile already existed, update it to verified
            if not created:
                profile.email_verified = True
                profile.save()
            
            # ✅ Auto-login immediately
            login(request, user)
            
            # ✅ Log registration
            logger.info(f"User registered and auto-verified: {user.username}")
            
            messages.success(request, "Welcome to PhiShield! Start protecting yourself from phishing attacks.")
            return redirect('phishield:dashboard')
    else:
        form = RegisterForm()
    
    return render(request, "phishield/register.html", {"form": form})


@login_required
def dashboard(request):
    """User dashboard with statistics and recent checks"""
    # ✅ FIXED: Use get_or_create to ensure profile exists
    profile, created = UserProfile.objects.get_or_create(
        user=request.user,
        defaults={
            'email_verified': True,
            'role': 'employee'
        }
    )
    
    # If profile was just created or wasn't verified, ensure it's verified
    if created or not profile.email_verified:
        profile.email_verified = True
        profile.save()
    
    # ✅ REMOVED verification warning - users get full access immediately
    
    links = SuspiciousLink.objects.filter(user=request.user).order_by("-date_checked")[:5]
    user_messages = SuspiciousMessage.objects.filter(user=request.user).order_by("-date_checked")[:5]

    recent_checks = []
    for link in links:
        recent_checks.append({
            "type": "URL",
            "content": link.url,
            "risk_level": link.risk_level,
            "date_checked": link.date_checked
        })

    for msg in user_messages:
        recent_checks.append({
            "type": "Message",
            "content": msg.message[:100] + "..." if len(msg.message) > 100 else msg.message,
            "risk_level": msg.risk_level,
            "date_checked": msg.date_checked
        })

    recent_checks.sort(key=lambda x: x["date_checked"], reverse=True)
    tip = random.choice(TIPS)

    total_checks = profile.total_checks
    threats_found = profile.threats_detected
    safe_checks = total_checks - threats_found

    # ✅ Log dashboard access
    logger.info(f"Dashboard accessed by: {request.user.username}")

    context = {
        "recent_checks": recent_checks[:5],
        "tip": tip,
        "total_checks": total_checks,
        "threats_found": threats_found,
        "safe_checks": safe_checks,
    }
    return render(request, "phishield/dashboard.html", context)


@login_required
def check_link(request):
    """Check URL for phishing indicators"""
    # ✅ REMOVED email verification - users can use immediately
    
    result = None
    flags = None
    tip = None

    if request.method == "POST":
        form = LinkForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data["url"]
            
            # ✅ Log URL check
            logger.info(f"URL check by {request.user.username}: {url}")
            
            risk_level, flag_list = analyze_url(url)
            
            # ✅ Save to database
            SuspiciousLink.objects.create(
                user=request.user,
                url=url,
                is_suspicious=(risk_level != 'safe'),
                risk_level=risk_level,
                flags=flag_list,
                date_checked=timezone.now()
            )
            
            # ✅ SAVE TO LOCAL LOG FILE
            save_analysis_result(
                user=request.user,
                check_type="URL",
                content=url,
                risk_level=risk_level,
                flags=flag_list
            )
            
            # ✅ FIXED: Use get_or_create for profile
            profile, created = UserProfile.objects.get_or_create(
                user=request.user,
                defaults={'email_verified': True, 'role': 'employee'}
            )
            profile.total_checks += 1
            if risk_level != 'safe':
                profile.threats_detected += 1
            profile.save()
            
            result = risk_level
            flags = flag_list
            tip = random.choice(TIPS)
            
            # ✅ Log result
            logger.info(f"URL analysis completed - Risk: {risk_level}")
    else:
        form = LinkForm()

    return render(request, "phishield/check_link.html", {
        "form": form,
        "result": result,
        "flags": flags,
        "tip": tip
    })


@login_required
def analyze_message_view(request):
    """Analyze text message for phishing indicators"""
    # ✅ REMOVED email verification - users can use immediately
    
    result = None
    flags = None
    tip = None

    if request.method == "POST":
        form = MessageForm(request.POST)
        if form.is_valid():
            message = form.cleaned_data["message"]
            
            # ✅ Log message analysis
            logger.info(f"Message analysis by {request.user.username}")
            
            risk_level, flag_list = analyze_message(message)
            
            # ✅ Save to database
            SuspiciousMessage.objects.create(
                user=request.user,
                message=message,
                is_suspicious=(risk_level != 'safe'),
                risk_level=risk_level,
                flags=flag_list,
                date_checked=timezone.now()
            )
            
            # ✅ SAVE TO LOCAL LOG FILE
            save_analysis_result(
                user=request.user,
                check_type="MESSAGE",
                content=message[:500],  # Limit length for log file
                risk_level=risk_level,
                flags=flag_list
            )
            
            # ✅ FIXED: Use get_or_create for profile
            profile, created = UserProfile.objects.get_or_create(
                user=request.user,
                defaults={'email_verified': True, 'role': 'employee'}
            )
            profile.total_checks += 1
            if risk_level != 'safe':
                profile.threats_detected += 1
            profile.save()
            
            result = risk_level
            # Split flags by | for better display
            if flag_list and flag_list.strip():
                flags = flag_list.split(' | ') if ' | ' in flag_list else [flag_list]
            else:
                flags = []
            tip = random.choice(TIPS)
            
            # ✅ Log result
            logger.info(f"Message analysis completed - Risk: {risk_level}")
    else:
        form = MessageForm()

    return render(request, "phishield/analyze_message.html", {
        "form": form,
        "result": result,
        "flags": flags,
        "tip": tip
    })


@login_required
def history(request):
    """View check history"""
    # ✅ REMOVED email verification - users can use immediately
    
    links = SuspiciousLink.objects.filter(user=request.user).order_by("-date_checked")
    user_messages = SuspiciousMessage.objects.filter(user=request.user).order_by("-date_checked")

    history_data = []
    for link in links:
        history_data.append({
            "type": "URL",
            "content": link.url,
            "risk_level": link.risk_level,
            "flags": link.flags,
            "date_checked": link.date_checked
        })

    for msg in user_messages:
        history_data.append({
            "type": "Message",
            "content": msg.message[:100] + "..." if len(msg.message) > 100 else msg.message,
            "risk_level": msg.risk_level,
            "flags": msg.flags,
            "date_checked": msg.date_checked
        })

    history_data.sort(key=lambda x: x["date_checked"], reverse=True)

    # ✅ Log history access
    logger.info(f"History accessed by: {request.user.username}")

    return render(request, "phishield/history.html", {"history": history_data})


def about_us(request):
    """About Us page with project information and team details"""
    # ✅ Log about page access
    logger.info("About Us page accessed")
    
    developers = [
        {"name": "Your Name", "role": "Lead Developer", "email": "your.email@example.com"},
        {"name": "Developer 2", "role": "Backend Developer", "email": "dev2@example.com"},
        {"name": "Developer 3", "role": "Frontend Developer", "email": "dev3@example.com"},
    ]
    
    project_management = [
        {"name": "PM Lead", "role": "Project Manager", "email": "pm@example.com"},
        {"name": "Team Lead", "role": "Technical Lead", "email": "techlead@example.com"},
    ]
    
    context = {
        "developers": developers,
        "project_management": project_management,
    }
    return render(request, "phishield/about_us.html", context)


@login_required
def contact(request):
    """Contact page with functional email logic"""
    if request.method == "POST":
        # 1. Get data from the HTML form
        name = request.POST.get('name')
        email_from_user = request.POST.get('email')
        subject_input = request.POST.get('subject')
        message = request.POST.get('message')
        
        # ✅ Log contact form submission
        logger.info(f"Contact form submitted by: {request.user.username}")
        
        # 2. Validate that fields are not empty
        if name and email_from_user and subject_input and message:
            # Check if email configuration is set
            if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
                logger.error("Email configuration missing: EMAIL_HOST_USER or EMAIL_HOST_PASSWORD not set")
                messages.error(request, "Email service is not configured. Please contact the administrator.")
                return redirect('phishield:contact')
            
            try:
                # 3. Create the email content
                full_message = f"""
                You have received a new contact inquiry via PhiShield.
                
                --------------------------------------------------
                Sender Name: {name}
                Sender Email: {email_from_user}
                Subject: {subject_input}
                --------------------------------------------------
                
                Message:
                {message}
                """
                
                # 4. Send the email using Settings
                send_mail(
                    subject=f"PhiShield Contact: {subject_input}",
                    message=full_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[settings.CONTACT_EMAIL], # Defined in settings.py
                    fail_silently=False,
                )
                
                # 5. Success Message
                messages.success(request, "Your message has been received! We'll get back to you soon.")
                return redirect('phishield:contact')
                
            except Exception as e:
                # Error Message if email fails
                logger.error(f"Failed to send email: {e}", exc_info=True)
                # Provide more helpful error message
                error_msg = str(e)
                if "authentication failed" in error_msg.lower() or "535" in error_msg:
                    messages.error(request, "Email authentication failed. Please check EMAIL_USER and EMAIL_PASSWORD in Railway variables. Make sure you're using a Gmail App Password, not your regular password.")
                elif "EMAIL_HOST_USER" in error_msg or "EMAIL_HOST_PASSWORD" in error_msg or "None" in error_msg:
                    messages.error(request, "Email configuration error. Please ensure EMAIL_USER and EMAIL_PASSWORD are set in Railway environment variables.")
                else:
                    messages.error(request, f"Error sending email: {error_msg}")
        else:
             messages.warning(request, 'Please fill in all fields.')
    
    return render(request, "phishield/contact.html")


@login_required
def view_logs(request):
    """View application logs in browser (for development only)"""
    # Only allow superusers to view logs for security
    if not request.user.is_superuser:
        messages.error(request, "Access denied. Only administrators can view logs.")
        return redirect('phishield:dashboard')
    
    log_file_path = 'phishield.log'
    
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as file:
                logs = file.read()
        else:
            logs = "No log file found. Logs will appear here once you start using the application."
    except Exception as e:
        logs = f"Error reading log file: {str(e)}"
    
    # ✅ Log that someone viewed the logs
    logger.info(f"Logs viewed by: {request.user.username}")
    
    return render(request, "phishield/view_logs.html", {"logs": logs})


@login_required
def view_analysis_logs(request):
    """View analysis results log files"""
    if not request.user.is_superuser:
        messages.error(request, "Access denied. Only administrators can view analysis logs.")
        return redirect('phishield:dashboard')
    
    log_dir = "analysis_logs"
    log_files = []
    
    if os.path.exists(log_dir):
        # Get all log files sorted by date (newest first)
        files = sorted([f for f in os.listdir(log_dir) if f.endswith('.log')], reverse=True)
        
        for file in files:
            file_path = os.path.join(log_dir, file)
            file_size = os.path.getsize(file_path)
            log_files.append({
                'name': file,
                'path': file_path,
                'size': file_size,
                'size_mb': round(file_size / 1024, 2)  # Size in KB
            })
    
    # If specific file is requested, show its content
    file_to_view = request.GET.get('file')
    file_content = None
    
    if file_to_view:
        file_path = os.path.join(log_dir, file_to_view)
        if os.path.exists(file_path) and file_to_view.endswith('.log'):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
            except Exception as e:
                file_content = f"Error reading file: {str(e)}"
    
    context = {
        'log_files': log_files,
        'file_content': file_content,
        'current_file': file_to_view
    }
    
    return render(request, "phishield/view_analysis_logs.html", context)

@login_required
def profile(request):
    """User profile page"""
    profile = request.user.profile
    
    # Get recent activity
    recent_links = SuspiciousLink.objects.filter(user=request.user).order_by('-date_checked')[:5]
    recent_messages = SuspiciousMessage.objects.filter(user=request.user).order_by('-date_checked')[:5]
    
    # Calculate some stats
    total_url_checks = SuspiciousLink.objects.filter(user=request.user).count()
    total_message_checks = SuspiciousMessage.objects.filter(user=request.user).count()
    
    context = {
        'profile': profile,
        'recent_links': recent_links,
        'recent_messages': recent_messages,
        'total_url_checks': total_url_checks,
        'total_message_checks': total_message_checks,
    }
    
    # ✅ Log profile access
    logger.info(f"Profile accessed by: {request.user.username}")
    
    return render(request, "phishield/profile.html", context)


@login_required
def settings_page(request):
    """User settings page"""
    profile = request.user.profile
    
    if request.method == "POST":
        # Handle settings form submission
        profile.receive_email_notifications = 'receive_email_notifications' in request.POST
        profile.receive_security_alerts = 'receive_security_alerts' in request.POST
        profile.dark_mode_enabled = 'dark_mode_enabled' in request.POST
        profile.auto_scan_links = 'auto_scan_links' in request.POST
        profile.show_tips = 'show_tips' in request.POST
        profile.language = request.POST.get('language', 'en')
        
        profile.save()
        
        messages.success(request, "Settings updated successfully!")
        
        # ✅ Log settings update
        logger.info(f"Settings updated by: {request.user.username}")
        
        return redirect('phishield:settings')
    
    context = {
        'profile': profile,
    }
    
    return render(request, "phishield/settings.html", context)


@login_required
def edit_profile(request):
    """Edit user profile"""
    profile = request.user.profile
    
    if request.method == "POST":
        # Handle form submission
        user = request.user
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        user.email = request.POST.get('email', '')
        user.save()
        
        profile.bio = request.POST.get('bio', '')
        profile.phone = request.POST.get('phone', '')
        profile.location = request.POST.get('location', '')
        profile.company = request.POST.get('company', '')
        profile.role = request.POST.get('role', 'employee')
        
        # Handle profile picture upload with validation
        if 'profile_picture' in request.FILES:
            uploaded_file = request.FILES['profile_picture']
            
            # Validate file size (5MB = 5242880 bytes)
            if uploaded_file.size > 5242880:
                messages.error(request, "Profile picture size exceeds 5MB limit. Please choose a smaller image.")
            else:
                # Validate file type by extension
                allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
                file_name = uploaded_file.name.lower()
                if any(file_name.endswith(ext) for ext in allowed_extensions):
                    # Delete old profile picture if it exists
                    if profile.profile_picture:
                        try:
                            old_picture_path = profile.profile_picture.path
                            if os.path.exists(old_picture_path):
                                os.remove(old_picture_path)
                        except Exception as e:
                            logger.warning(f"Could not delete old profile picture: {e}")
                    
                    profile.profile_picture = uploaded_file
                else:
                    messages.error(request, "Invalid file type. Please upload a JPG, PNG, GIF, or WebP image.")
        
        profile.save()
        
        messages.success(request, "Profile updated successfully!")
        
        # ✅ Log profile update
        logger.info(f"Profile updated by: {request.user.username}")
        
        return redirect('phishield:profile')
    
    context = {
        'profile': profile,
    }
    
    return render(request, "phishield/edit_profile.html", context)


@login_required
def change_password(request):
    """Change user password"""
    if request.method == "POST":
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        user = request.user
        
        # Validate current password
        if not user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return redirect('phishield:change_password')
        
        # Validate new passwords match
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect('phishield:change_password')
        
        # Validate password strength
        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return redirect('phishield:change_password')
        
        # Change password
        user.set_password(new_password)
        user.save()
        
        # Update session auth hash
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)
        
        messages.success(request, "Password changed successfully!")
        
        # ✅ Log password change
        logger.info(f"Password changed by: {request.user.username}")
        
        return redirect('phishield:profile')
    
    return render(request, "phishield/change_password.html")