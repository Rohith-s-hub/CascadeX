# accounts/urls.py

from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    ProfileView,
    ChangePasswordView,
    TokenRefreshView,
)
from .oauth_views import (
    GoogleOAuthInitView,
    GoogleOAuthCallbackView,
    GitHubOAuthInitView,
    GitHubOAuthCallbackView,
    OAuthStatusView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),

    # OAuth
    path('oauth/google/', GoogleOAuthInitView.as_view(), name='google-oauth-init'),
    path('oauth/google/callback/', GoogleOAuthCallbackView.as_view(), name='google-oauth-callback'),
    path('oauth/github/', GitHubOAuthInitView.as_view(), name='github-oauth-init'),
    path('oauth/github/callback/', GitHubOAuthCallbackView.as_view(), name='github-oauth-callback'),
    path('oauth/status/', OAuthStatusView.as_view(), name='oauth-status'),
]