import jwt
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.conf import settings


from rest_framework import generics, status, views, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from user.serializers import (
    EmailVeryficationSerializer,
    LoginSerializer,
    LogoutSerializer,
    RegistrationSerializer,
    RequestPasswordResetEmailSerializer,
    ResendVerificationEmailSerializer,
    SetNewPasswordSerializer,
)
from common.mail.lib import EmailData, Mail


User = get_user_model()


class RegistrationView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        input_data = request.data
        serializer = self.serializer_class(data=input_data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        ### Sendring email
        user = User.objects.get(email=input_data["email"])
        user_email: str = user.email  # type: ignore

        token = RefreshToken.for_user(user=user).access_token  # type: ignore

        current_site_domain = get_current_site(request).domain
        relative_lint = reverse("authentication:verify-email")
        verification_link = (
            f"https://{current_site_domain}{relative_lint}?token={token}"
        )

        email_body = (
            f"Hi {user_email}",
            "Use the link below to verify your email.",
            verification_link,
        )
        Mail.send_email(
            EmailData(
                subject="Example Email Veryfikation",
                body="\n".join(email_body),
                to=(user_email,),
            )
        )

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class EmailVeryficationView(views.APIView):
    serializer_class = EmailVeryficationSerializer

    def get(self, request):
        token = request.GET.get("token")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])
            if not user.is_verified:  # type: ignore
                user.is_verified = True  # type: ignore
                user.is_active = True
                user.save()
            return Response(("Email Successfully verified",), status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return Response(
                {"error": "Activation Expired"}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.exceptions.DecodeError as identifier:
            return Response(
                {"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )


class ResendVerificationEmailView(views.APIView):
    serializer_class = ResendVerificationEmailSerializer

    def post(self, request):
        input_data = request.data
        email = input_data["email"]

        try:
            if User.objects.filter(email=email).exists:
                user = User.objects.get(email__exact=email)
                token = RefreshToken.for_user(user=user).access_token  # type: ignore
                current_site_domain = get_current_site(request=request).domain
                relative_link = reverse("authentication:verify-email")
                verification_link = (
                    f"https://{current_site_domain}{relative_link}?token={token}"
                )

                email_body = (
                    f"Hi {email}",
                    "Use the link below to verify your email.",
                    "If you were not expecting any account verification email, please ignore this.",
                    verification_link,
                )

                Mail.send_email(
                    EmailData(
                        subject="Example Email Veryfikation",
                        body="\n".join(email_body),
                        to=(email,),
                    )
                )
                return Response(
                    {"Verification Email sent. Check your inbox."},
                    status=status.HTTP_200_OK,
                )
        except User.DoesNotExist as exc:
            return Response(
                {"The email address does not not match any user account."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmailView(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data["email"]

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))  # type: ignore
            token = PasswordResetTokenGenerator().make_token(user=user)

            current_site = get_current_site(request=request).domain
            relative_link = reverse(
                "authentication:password-reset-confirm",
                kwargs={"uidb64": uidb64, "token": token},
            )
            abs_url = f"http://{current_site}{relative_link}"

            email_body = (
                "Hello!",
                "Use the link below to reset your password",
                abs_url,
            )

            Mail.send_email(
                EmailData(
                    subject="Reset your password",
                    body="\n".join(email_body),
                    to=(user.email,),  # type: ignore
                )
            )

        return Response(
            {"Success": "Password reset email sent"}, status=status.HTTP_200_OK
        )


class PasswordResetTokenValidationView(generics.GenericAPIView):
    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {
                        "Error": "Password reset link is expired! Please request for a new one!"
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            return Response(
                {
                    "Success": True,
                    "Message": "Valid Credentials",
                    "uidb64": uidb64,
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )

        except DjangoUnicodeDecodeError as exc:
            if not PasswordResetTokenGenerator().check_token(user=user, token=None):
                return Response(
                    {"Error": "Token is not valid! Please request for a new one!"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )


class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"success": True, "message": "Password changed successfully"},
            status=status.HTTP_200_OK,
        )


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_class = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"success": True, "message": "Logged out successfully"},
            status=status.HTTP_200_OK,
        )
