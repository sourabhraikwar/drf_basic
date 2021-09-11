
from django.contrib.auth import authenticate
from rest_framework import serializers

from django.contrib.auth import get_user_model
User = get_user_model()

def get_and_authenticate_user(username, password):
    user_qs = User.objects.filter(username=username)
    user_exists = user_qs.last().check_password(password) if user_qs.exists() else False
    if not user_exists:
        raise serializers.ValidationError("Invalid username/password. Please try again!")
    return user_qs

def create_user_account(username, email, password, first_name="",
                        last_name="", **extra_fields):
    user = get_user_model().objects.create_user(
        username=username,
        email=email, 
        password=password, 
        first_name=first_name,
        last_name=last_name, **extra_fields)
    return user