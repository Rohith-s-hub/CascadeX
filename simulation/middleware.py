# simulation/middleware.py
"""
Security Middleware
═══════════════════════════════════════════════════════════════
- API Key authentication
- Role-based access control
- Rate limiting
"""

import hashlib
import time
import logging
from collections import defaultdict
from datetime import datetime

from django.http import JsonResponse
from django.utils import timezone

logger = logging.getLogger(__name__)


class APIKeyMiddleware:
    """
    Authenticate requests via API key header
    Header: X-API-Key: <key>
    """

    EXEMPT_PATHS = [
        '/api/cve/health/',
        '/admin/',
        '/static/',
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # Skip exempt paths
        if any(path.startswith(p)
               for p in self.EXEMPT_PATHS):
            return self.get_response(request)

        # Check for API key
        api_key = request.META.get(
            'HTTP_X_API_KEY'
        )

        if api_key:
            try:
                from simulation.models import APIKey

                key_obj = APIKey.objects.select_related(
                    'user'
                ).get(
                    key=api_key,
                    is_active=True,
                )

                # Check expiry
                if (key_obj.expires_at
                    and key_obj.expires_at
                    < timezone.now()):
                    return JsonResponse(
                        {
                            'error': 'API key expired',
                        },
                        status=401,
                    )

                # Attach user to request
                request.user = key_obj.user
                request.api_key = key_obj

                # Update last used
                key_obj.last_used = timezone.now()
                key_obj.save(
                    update_fields=['last_used']
                )

            except Exception:
                return JsonResponse(
                    {'error': 'Invalid API key'},
                    status=401,
                )

        return self.get_response(request)


class RBACMiddleware:
    """
    Role-based access control
    """

    # Path → required role mapping
    ROLE_REQUIREMENTS = {
        '/api/cve/scan/': ['admin', 'analyst'],
        '/api/cve/mitigate/': ['admin', 'analyst'],
        '/api/cve/assets/discover/': [
            'admin', 'analyst',
        ],
        '/api/cve/validate/': ['admin', 'analyst'],
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # Check if path requires specific role
        required_roles = None
        for pattern, roles in (
            self.ROLE_REQUIREMENTS.items()
        ):
            if path.startswith(pattern):
                required_roles = roles
                break

        if required_roles and request.user.is_authenticated:
            try:
                profile = request.user.security_profile
                if profile.role not in required_roles:
                    return JsonResponse(
                        {
                            'error': 'Insufficient permissions',
                            'required_role': required_roles,
                            'your_role': profile.role,
                        },
                        status=403,
                    )
            except Exception:
                pass  # No profile = allow (for now)

        return self.get_response(request)


class RateLimitMiddleware:
    """
    Simple in-memory rate limiting
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.requests = defaultdict(list)
        self.default_limit = 100  # per minute

    def __call__(self, request):
        # Get client identifier
        if hasattr(request, 'api_key'):
            client_id = f"key:{request.api_key.key[:8]}"
            limit = request.api_key.rate_limit
        else:
            client_id = (
                f"ip:{self._get_client_ip(request)}"
            )
            limit = self.default_limit

        # Check rate limit
        now = time.time()
        minute_ago = now - 60

        # Clean old requests
        self.requests[client_id] = [
            t for t in self.requests[client_id]
            if t > minute_ago
        ]

        if len(self.requests[client_id]) >= limit:
            return JsonResponse(
                {
                    'error': 'Rate limit exceeded',
                    'limit': limit,
                    'retry_after': 60,
                },
                status=429,
            )

        self.requests[client_id].append(now)
        return self.get_response(request)

    def _get_client_ip(self, request) -> str:
        xff = request.META.get(
            'HTTP_X_FORWARDED_FOR'
        )
        if xff:
            return xff.split(',')[0].strip()
        return request.META.get(
            'REMOTE_ADDR', 'unknown'
        )