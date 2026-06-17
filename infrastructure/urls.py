from django.urls import path
from . import views

urlpatterns = [
    path('seed/', views.seed_infrastructure, name='seed_infrastructure'),
]
