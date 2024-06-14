from django.urls import path

from . import views

app_name = "user"

urlpatterns = [
    path("users/", views.UserList.as_view(), name="user-list"),
    path("users/<int:pk>/", views.UserDetail.as_view(), name="user-detail"),
]
