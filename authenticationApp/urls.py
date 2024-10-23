from django.urls import path
from .views import RegisterView, LoginView, InviteUserView, ChangePasswordView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('invite-user/', InviteUserView.as_view(), name='invite-user'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
