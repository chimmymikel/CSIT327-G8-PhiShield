"""
URL configuration for phishield_project project.
"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("phishield.urls")),
    
    # Add password reset URLs - WITHOUT namespace in main urls.py
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(
             template_name='phishield/password_reset.html'
         ), 
         name='password_reset'),  
    path('password-reset/done/', 
         auth_views.PasswordResetDoneView.as_view(
             template_name='phishield/password_reset_done.html'
         ), 
         name='password_reset_done'), 
    path('password-reset-confirm/<uidb64>/<token>/', 
         auth_views.PasswordResetConfirmView.as_view(
             template_name='phishield/password_reset_confirm.html'
         ), 
         name='password_reset_confirm'),  
    path('password-reset-complete/', 
         auth_views.PasswordResetCompleteView.as_view(
             template_name='phishield/password_reset_complete.html'
         ), 
         name='password_reset_complete'),  
]

# Serve media files
# Note: In production, consider using cloud storage (AWS S3, Cloudinary) or Railway Volumes
# for persistent storage, as Railway's filesystem is ephemeral
if settings.DEBUG:
    # Development: Django serves media files
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    # Production: Serve media files through Django (not ideal but works)
    # For better performance, use cloud storage or a CDN
    from django.views.static import serve
    from django.urls import re_path
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
    ]