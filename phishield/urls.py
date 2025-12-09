from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views
from . import views

app_name = 'phishield'

urlpatterns = [
    # --------------------------
    # Core Pages
    # --------------------------
    path("", views.index, name="index"),
    path("register/", views.register, name="register"),
    path(
        "login/",
        auth_views.LoginView.as_view(
            template_name="phishield/login.html",
            redirect_authenticated_user=True
        ),
        name="login"
    ),
    path(
        "logout/",
        auth_views.LogoutView.as_view(next_page='phishield:login'),
        name="logout"
    ),
    path("dashboard/", views.dashboard, name="dashboard"),
    
    # --------------------------
    # Analysis Tools
    # --------------------------
    path("check-link/", views.check_link, name="check_link"),
    path("analyze-message/", views.analyze_message_view, name="analyze_message"),
    path("history/", views.history, name="history"),
    
    # --------------------------
    # User Profile & Settings
    # --------------------------
    path("profile/", views.profile, name="profile"),
    path("profile/edit/", views.edit_profile, name="edit_profile"),
    path("profile/change-password/", views.change_password, name="change_password"),
    path("profile/delete-account/", views.delete_account, name="delete_account"),
    path("settings/", views.settings_page, name="settings"),
    
    # --------------------------
    # Information Pages
    # --------------------------
    path("about/", views.about_us, name="about_us"),
    path("contact/", views.contact, name="contact"),
    
    # --------------------------
    # Log Viewing Pages
    # --------------------------
    path("logs/", views.view_logs, name="view_logs"),
    path("analysis-logs/", views.view_analysis_logs, name="view_analysis_logs"),

    # --------------------------
    # Password Reset Flow
    # --------------------------
    path(
        "password-reset/",
        auth_views.PasswordResetView.as_view(
            template_name="phishield/password_reset_form.html",
            email_template_name="phishield/password_reset_email.html",
            subject_template_name="phishield/password_reset_subject.txt",
            success_url=reverse_lazy("phishield:password_reset_done"),
        ),
        name="password_reset"
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="phishield/password_reset_done.html"
        ),
        name="password_reset_done"
    ),
    path(
        "password-reset-confirm/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="phishield/password_reset_confirm.html",
            success_url=reverse_lazy("phishield:password_reset_complete"),
        ),
        name="password_reset_confirm"
    ),
    path(
        "password-reset-complete/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="phishield/password_reset_complete.html"
        ),
        name="password_reset_complete"
    ),
]