# accounts/oauth_views.py
"""
OAuth Views — Google and GitHub SSO
Bridges OAuth tokens to CascadeX JWT tokens.
"""

import logging
import secrets
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.utils import timezone
from django.views import View
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)
User = get_user_model()


def _issue_jwt(user) -> dict:
    """Issue CascadeX JWT tokens for a user."""
    refresh = RefreshToken.for_user(user)
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }


def _user_to_dict(user) -> dict:
    """Serialize user for frontend."""
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'role': getattr(user, 'role', 'viewer'),
        'organization': getattr(user, 'organization', ''),
    }


def _get_or_create_oauth_user(email: str, first_name: str, last_name: str, provider: str) -> tuple:
    """
    Get or create a user from OAuth data.
    Returns (user, created)
    """
    try:
        user = User.objects.get(email=email)
        # Update name if missing
        if not user.first_name and first_name:
            user.first_name = first_name
            user.last_name = last_name
            user.save(update_fields=['first_name', 'last_name'])
        return user, False
    except User.DoesNotExist:
        # Create new user
        username_base = email.split('@')[0].replace('.', '_').replace('+', '_')
        username = username_base
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{username_base}_{counter}"
            counter += 1

        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=None,  # OAuth users have no password
        )
        logger.info(f"New OAuth user created: {email} via {provider}")
        return user, True


class GoogleOAuthInitView(APIView):
    """
    GET: Redirect user to Google OAuth consent screen.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
            from allauth.socialaccount.providers.oauth2.client import OAuth2Client

            client_id = settings.SOCIALACCOUNT_PROVIDERS['google']['APP']['client_id']

            if not client_id:
                return Response(
                    {'error': 'Google OAuth not configured'},
                    status=503
                )

            # Generate state for CSRF protection
            state = secrets.token_urlsafe(32)
            request.session['oauth_state'] = state
            request.session['oauth_provider'] = 'google'

            params = {
                'client_id': client_id,
                'redirect_uri': request.build_absolute_uri('/api/auth/oauth/google/callback/'),
                'response_type': 'code',
                'scope': 'openid email profile',
                'state': state,
                'access_type': 'online',
            }

            google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
            return HttpResponseRedirect(google_auth_url)

        except Exception as e:
            logger.error(f"Google OAuth init failed: {e}", exc_info=True)
            failure_url = getattr(settings, 'OAUTH_CALLBACK_FAILURE_URL', '/login?error=oauth_failed')
            return HttpResponseRedirect(failure_url)


class GoogleOAuthCallbackView(APIView):
    """
    GET: Handle Google OAuth callback.
    Exchange code for token, get user info, issue JWT.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        import requests as http_requests

        failure_url = getattr(settings, 'OAUTH_CALLBACK_FAILURE_URL', '/login?error=oauth_failed')
        success_url = getattr(settings, 'OAUTH_CALLBACK_SUCCESS_URL', '/dashboard')

        try:
            code = request.GET.get('code')
            state = request.GET.get('state')
            error = request.GET.get('error')

            if error:
                logger.warning(f"Google OAuth error: {error}")
                return HttpResponseRedirect(f"{failure_url}&reason={error}")

            if not code:
                return HttpResponseRedirect(failure_url)

            # Validate state (CSRF protection)
            session_state = request.session.get('oauth_state')
            if state != session_state:
                logger.warning("OAuth state mismatch — possible CSRF attack")
                return HttpResponseRedirect(f"{failure_url}&reason=state_mismatch")

            # Exchange code for access token
            client_id = settings.SOCIALACCOUNT_PROVIDERS['google']['APP']['client_id']
            client_secret = settings.SOCIALACCOUNT_PROVIDERS['google']['APP']['secret']

            token_response = http_requests.post(
                'https://oauth2.googleapis.com/token',
                data={
                    'code': code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': request.build_absolute_uri('/api/auth/oauth/google/callback/'),
                    'grant_type': 'authorization_code',
                },
                timeout=10,
            )

            if not token_response.ok:
                logger.error(f"Google token exchange failed: {token_response.text}")
                return HttpResponseRedirect(failure_url)

            token_data = token_response.json()
            access_token = token_data.get('access_token')

            # Get user info from Google
            userinfo_response = http_requests.get(
                'https://www.googleapis.com/oauth2/v2/userinfo',
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10,
            )

            if not userinfo_response.ok:
                return HttpResponseRedirect(failure_url)

            userinfo = userinfo_response.json()
            email = userinfo.get('email')
            first_name = userinfo.get('given_name', '')
            last_name = userinfo.get('family_name', '')

            if not email:
                return HttpResponseRedirect(f"{failure_url}&reason=no_email")

            # Get or create user
            user, created = _get_or_create_oauth_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                provider='google',
            )

            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])

            # Issue JWT tokens
            tokens = _issue_jwt(user)

            # Clear OAuth session state
            request.session.pop('oauth_state', None)
            request.session.pop('oauth_provider', None)

            # Redirect to frontend with tokens in URL fragment
            # Frontend reads these from the URL hash
            redirect_url = (
                f"{success_url}"
                f"#oauth_success=1"
                f"&access={tokens['access']}"
                f"&refresh={tokens['refresh']}"
                f"&user_id={user.id}"
                f"&username={user.username}"
                f"&email={user.email}"
                f"&first_name={user.first_name}"
            )

            logger.info(f"Google OAuth success: {email} ({'new' if created else 'existing'} user)")
            return HttpResponseRedirect(redirect_url)

        except Exception as e:
            logger.error(f"Google OAuth callback failed: {e}", exc_info=True)
            return HttpResponseRedirect(failure_url)


class GitHubOAuthInitView(APIView):
    """
    GET: Redirect user to GitHub OAuth consent screen.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            client_id = settings.SOCIALACCOUNT_PROVIDERS['github']['APP']['client_id']

            if not client_id:
                return Response(
                    {'error': 'GitHub OAuth not configured'},
                    status=503
                )

            state = secrets.token_urlsafe(32)
            request.session['oauth_state'] = state
            request.session['oauth_provider'] = 'github'

            params = {
                'client_id': client_id,
                'redirect_uri': request.build_absolute_uri('/api/auth/oauth/github/callback/'),
                'scope': 'user:email',
                'state': state,
            }

            github_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
            return HttpResponseRedirect(github_auth_url)

        except Exception as e:
            logger.error(f"GitHub OAuth init failed: {e}", exc_info=True)
            failure_url = getattr(settings, 'OAUTH_CALLBACK_FAILURE_URL', '/login?error=oauth_failed')
            return HttpResponseRedirect(failure_url)


class GitHubOAuthCallbackView(APIView):
    """
    GET: Handle GitHub OAuth callback.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        import requests as http_requests

        failure_url = getattr(settings, 'OAUTH_CALLBACK_FAILURE_URL', '/login?error=oauth_failed')
        success_url = getattr(settings, 'OAUTH_CALLBACK_SUCCESS_URL', '/dashboard')

        try:
            code = request.GET.get('code')
            state = request.GET.get('state')
            error = request.GET.get('error')

            if error:
                return HttpResponseRedirect(f"{failure_url}&reason={error}")

            if not code:
                return HttpResponseRedirect(failure_url)

            # Validate state
            session_state = request.session.get('oauth_state')
            if state != session_state:
                logger.warning("GitHub OAuth state mismatch")
                return HttpResponseRedirect(f"{failure_url}&reason=state_mismatch")

            # Exchange code for token
            client_id = settings.SOCIALACCOUNT_PROVIDERS['github']['APP']['client_id']
            client_secret = settings.SOCIALACCOUNT_PROVIDERS['github']['APP']['secret']

            token_response = http_requests.post(
                'https://github.com/login/oauth/access_token',
                data={
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'code': code,
                    'redirect_uri': request.build_absolute_uri('/api/auth/oauth/github/callback/'),
                },
                headers={'Accept': 'application/json'},
                timeout=10,
            )

            if not token_response.ok:
                return HttpResponseRedirect(failure_url)

            token_data = token_response.json()
            access_token = token_data.get('access_token')

            if not access_token:
                return HttpResponseRedirect(failure_url)

            # Get user info
            user_response = http_requests.get(
                'https://api.github.com/user',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                },
                timeout=10,
            )

            if not user_response.ok:
                return HttpResponseRedirect(failure_url)

            github_user = user_response.json()

            # Get email (may be private)
            email = github_user.get('email')
            if not email:
                email_response = http_requests.get(
                    'https://api.github.com/user/emails',
                    headers={
                        'Authorization': f'Bearer {access_token}',
                        'Accept': 'application/vnd.github.v3+json',
                    },
                    timeout=10,
                )
                if email_response.ok:
                    emails = email_response.json()
                    primary = next(
                        (e['email'] for e in emails if e.get('primary') and e.get('verified')),
                        None
                    )
                    email = primary or (emails[0]['email'] if emails else None)

            if not email:
                return HttpResponseRedirect(f"{failure_url}&reason=no_email")

            # Parse name
            full_name = github_user.get('name', '') or ''
            parts = full_name.strip().split(' ', 1)
            first_name = parts[0] if parts else github_user.get('login', '')
            last_name = parts[1] if len(parts) > 1 else ''

            # Get or create user
            user, created = _get_or_create_oauth_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                provider='github',
            )

            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])

            tokens = _issue_jwt(user)

            request.session.pop('oauth_state', None)
            request.session.pop('oauth_provider', None)

            redirect_url = (
                f"{success_url}"
                f"#oauth_success=1"
                f"&access={tokens['access']}"
                f"&refresh={tokens['refresh']}"
                f"&user_id={user.id}"
                f"&username={user.username}"
                f"&email={user.email}"
                f"&first_name={user.first_name}"
            )

            logger.info(f"GitHub OAuth success: {email} ({'new' if created else 'existing'} user)")
            return HttpResponseRedirect(redirect_url)

        except Exception as e:
            logger.error(f"GitHub OAuth callback failed: {e}", exc_info=True)
            return HttpResponseRedirect(failure_url)


class OAuthStatusView(APIView):
    """
    GET: Check which OAuth providers are configured.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        google_configured = bool(
            settings.SOCIALACCOUNT_PROVIDERS.get('google', {})
            .get('APP', {}).get('client_id')
        )
        github_configured = bool(
            settings.SOCIALACCOUNT_PROVIDERS.get('github', {})
            .get('APP', {}).get('client_id')
        )
        return Response({
            'google': google_configured,
            'github': github_configured,
        })
