from django.urls import path, include
from .views import api_root

urlpatterns = [
    path("", api_root, name="main"),
    path("authentication/", include("public.api.v1.authentication.urls")),
    path("user/", include("public.api.v1.user.urls")),
]
