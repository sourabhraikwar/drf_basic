from django.urls import path
from auth.views import UpdateProfileView


urlpatterns = [
    path(
        "update_profile/<int:pk>/",
        UpdateProfileView.as_view(),
        name="auth_update_profile",
    ),
]
