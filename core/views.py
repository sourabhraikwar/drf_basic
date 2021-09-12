from django.shortcuts import get_object_or_404
from core.serializers import *
from rest_framework import viewsets
from rest_framework.response import Response
from django.contrib.auth import get_user_model, logout
from rest_framework.permissions import IsAuthenticated, AllowAny
from .utils import get_and_authenticate_user
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from . import serializers
from .utils import get_and_authenticate_user


User = get_user_model()


class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [
        AllowAny,
    ]
    queryset = User.objects.all()
    serializer_class = serializers.EmptySerializer
    serializer_classes = {
        "register": serializers.UserRegisterSerializer,
        "password_change": serializers.PasswordChangeSerializer,
        "list_users": serializers.ListUserSerializer,
        "retrieve_user": serializers.RetrieveUserSerializer,
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
    def password_change(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

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

    def get_serializer_class(self):
        if not isinstance(self.serializer_classes, dict):
            raise ImproperlyConfigured("serializer_classes should be a dict mapping.")

        if self.action in self.serializer_classes.keys():
            return self.serializer_classes[self.action]
        return super().get_serializer_class()
