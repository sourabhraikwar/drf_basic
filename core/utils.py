from django.contrib.auth import authenticate
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.mail import send_mail

User = get_user_model()


def create_user_account(
    username, email, password, first_name="", last_name="", **extra_fields
):
    user = get_user_model().objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        **extra_fields
    )
    return user


def send_email(message: str, receivers: list):
    send_mail(
        "Email Verification",
        message,
        settings.EMAIL_HOST,
        receivers,
        fail_silently=False,
    )
