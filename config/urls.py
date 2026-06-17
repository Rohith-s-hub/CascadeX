# config/urls.py

from django.contrib import admin
from django.urls import path, include, re_path

from core import views as core_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    path('api/simulation/', include('simulation.urls')),
    re_path(r"^assets/(?P<asset_path>.+)$", core_views.frontend_asset, name="frontend-asset"),
    path("", core_views.frontend_app, name="frontend-root"),
    re_path(r"^(?!api/|admin/).*$", core_views.frontend_app, name="frontend-spa"),
]
