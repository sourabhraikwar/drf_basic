from django.shortcuts import get_object_or_404
from core.serializers import *
from rest_framework import viewsets
from rest_framework.response import Response
from django.contrib.auth import get_user_model, logout
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.core.exceptions import ImproperlyConfigured
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from . import serializers


User = get_user_model()


class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [
        AllowAny,
    ]
    queryset = User.objects.all()
    serializer_class = serializers.EmptySerializer
    serializer_classes = {
        "register": serializers.UserRegisterSerializer,
        "forget_password": serializers.ForgetPasswordSerializer,
        "list_users": serializers.ListUserSerializer,
        "retrieve_user": serializers.RetrieveUserSerializer,
        "send_email_verification": serializers.SendEmailVerificationSerializer,
        "verify_email": serializers.VerifyEmailSerializer,
    }

    @action(
        methods=[
            "POST",
        ],
        detail=False,
    )
    def register(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = create_user_account(**serializer.validated_data)
        data = serializers.AuthUserSerializer(user).data
        return Response(data=data, status=status.HTTP_201_CREATED)

    @action(
        methods=[
            "POST",
        ],
        detail=False,
    )
    def logout(self, request):
        # Todo: need to blacklist token
        data = {"success": "Sucessfully logged out"}
        return Response(data=data, status=status.HTTP_200_OK)

    @action(
        methods=["POST"],
        detail=False,
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def forget_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.request.user, serializer.validated_data)
        data = {"success": "Password changed successfully"}
        return Response(data=data, status=status.HTTP_200_OK)

    @action(
        methods=[
            "GET",
        ],
        detail=False,
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def list_users(self, request):
        user_qs = self.get_queryset()
        serializer = self.get_serializer(user_qs, many=True)
        return Response(serializer.data)

    @action(
        methods=[
            "GET",
        ],
        detail=False,
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def retrieve_user(self, request):
        user_qs = self.get_queryset().filter(id=self.request.GET.get("id", None))
        serializer = self.get_serializer(user_qs, many=True)
        return Response(serializer.data)

    @action(
        methods=[
            "POST",
        ],
        detail=False,
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def send_email_verification(self, request):
        serializer = self.get_serializer(request.data)
        serializer.is_valid(raise_exception=True)
        serializer.send_email(self.request)
        data = {"success": "Verification code sent in your registered email id please verifiy"}
        return Response(data=data, status=status.HTTP_200_OK)

    def verify_email(self, request):
        serializer = self.get_serializer(request.data)
        serializer.is_valid(raise_exception=True)
        serializer.send_email(self.request)
        data = {"success": "Verification code sent in your registered email id please verifiy"}
        return Response(data=data, status=status.HTTP_200_OK)

    def get_serializer_class(self):
        if not isinstance(self.serializer_classes, dict):
            raise ImproperlyConfigured("serializer_classes should be a dict mapping.")

        if self.action in self.serializer_classes.keys():
            return self.serializer_classes[self.action]
        return super().get_serializer_class()


class UpdateProfileView(generics.UpdateAPIView):

    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.UpdateUserSerializer