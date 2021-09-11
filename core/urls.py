from django.urls import path, include
from .views import UserViewSet


user_list = UserViewSet.as_view({'get': 'list'})
user_detail = UserViewSet.as_view({'get': 'retrieve'})
update_user = UserViewSet.as_view({'put': 'update'})
delete_user = UserViewSet.as_view({'delete': 'destroy'})

urlpatterns = [
    path('list/', user_list, name="list_users"),
    path('retrieve/<int:pk>', user_detail, name="retrive_user_by_id"),
    path('update/<int:pk>', update_user, name="update_user"),
    path('delete_user/<int:pk>', delete_user, name="delete_user"),
] 
