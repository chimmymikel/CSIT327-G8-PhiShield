from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .email_verifier import validate_email_domain, SimpleEmailVerifier


class LinkForm(forms.Form):
    url = forms.CharField(
        label="Enter URL to Check",
        max_length=500,
        widget=forms.TextInput(attrs={
            "class": "form-control form-control-lg",
            "placeholder": "https://example.com or example.com",
            "autocomplete": "off"
        })
    )
    
    def clean_url(self):
        """Validate and normalize URL - accepts URLs with or without protocol"""
        url = self.cleaned_data.get('url', '').strip()
        
        if not url:
            raise forms.ValidationError("Please enter a URL.")
        
        # Remove whitespace
        url = url.strip()
        
        # Basic validation - check if it looks like a URL or domain
        if not (url.startswith(('http://', 'https://')) or 
                '.' in url or 
                url.startswith('www.')):
            raise forms.ValidationError("Please enter a valid URL or domain name.")
        
        # If no protocol, add https://
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url


class MessageForm(forms.Form):
    message = forms.CharField(
        label="Paste Suspicious Message",
        widget=forms.Textarea(attrs={
            "class": "form-control",
            "rows": 6,
            "placeholder": "Paste the suspicious text or email content here..."
        })
    )


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        validators=[validate_email_domain],
        widget=forms.EmailInput(attrs={
            "class": "form-control",
            "placeholder": "your.real.email@example.com",
            "autocomplete": "email"
        })
    )
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "First Name"
        })
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "Last Name"
        })
    )
    
    # Add terms agreement
    agree_to_terms = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            "class": "form-check-input"
        }),
        error_messages={'required': 'You must agree to the terms and conditions'}
    )

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['username', 'password1', 'password2']:
            self.fields[field_name].widget.attrs.update({"class": "form-control"})
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            email = email.lower().strip()
            
            # Check if email already exists
            if User.objects.filter(email=email).exists():
                raise forms.ValidationError("This email address is already registered.")
            
            # Additional validation
            is_valid, message = SimpleEmailVerifier.is_valid_email(email)
            if not is_valid:
                raise forms.ValidationError(message)
                
        return email


class EmailVerificationForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            "class": "form-control form-control-lg",
            "placeholder": "Enter your email to resend verification"
        })
    )
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            is_valid, message = SimpleEmailVerifier.is_valid_email(email)
            if not is_valid:
                raise forms.ValidationError(message)
        return email