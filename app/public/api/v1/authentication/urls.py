from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

app_name = "authentication"

urlpatterns = [
    path("register/", views.RegistrationView.as_view(), name="register"),
    path("verify-email/", views.EmailVeryficationView.as_view(), name="verify-email"),
    path(
        "resend-verification-email/",
        views.ResendVerificationEmailView.as_view(),
        name="resend-verification-email",
    ),
    path(
        "request-password-reset-email/",
        views.RequestPasswordResetEmailView.as_view(),
        name="request-password-reset-email",
    ),
    path(
        "password-reset/<uidb64>/<token>/",
        views.PasswordResetTokenValidationView.as_view(),
        name="password-reset-confirm",
    ),
    path("password-reset/", views.SetNewPasswordView.as_view(), name="password-reset"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("refresh-token/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
]
