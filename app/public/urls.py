from django.urls import path, include

urlpatterns = [path("api/v1/", include("public.api.v1.urls"))]
