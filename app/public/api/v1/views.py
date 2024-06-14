from rest_framework.decorators import api_view
from rest_framework.reverse import reverse
from rest_framework.response import Response


@api_view(["GET", "HEAD"])
def api_root(request, format=None):
    return Response(
        {
            "register": str(
                reverse("authentication:register", request=request, format=None)
            ),
            "login": str(reverse("authentication:login", request=request, format=None)),
            "refresh-token": str(
                reverse("authentication:token_refresh", request=request, format=None)
            ),
            "resend-verification-email": str(
                reverse(
                    "authentication:resend-verification-email",
                    request=request,
                    format=None,
                )
            ),
            "request-password-reset-email": str(
                reverse(
                    "authentication:request-password-reset-email",
                    request=request,
                    format=None,
                )
            ),
            "password-reset": str(
                reverse("authentication:password-reset", request=request, format=None)
            ),
            "logout": str(
                reverse("authentication:logout", request=request, format=None)
            ),
            "user-list": str(reverse("user:user-list", request=request, format=None)),
        }
    )
