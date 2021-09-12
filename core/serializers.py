from rest_framework import serializers
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth import get_user_model, password_validation
from .utils import create_user_account
from django.contrib.auth import get_user_model

User = get_user_model()


class AuthUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "is_active",
        )
        read_only_fields = (
            "id",
            "is_active",
        )


class EmptySerializer(serializers.Serializer):
    pass


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    A user serializer for registering the user
    """

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "first_name", "last_name")

    def validate_email(self, value):
        user = User.objects.filter(email=value)
        if user:
            raise serializers.ValidationError("Email is already taken")
        return BaseUserManager.normalize_email(value)

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_current_password(self, value):
        if not self.context["request"].user.check_password(value):
            raise serializers.ValidationError("Current password does not match")
        return value

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value


class ListUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name")


class RetrieveUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name")
