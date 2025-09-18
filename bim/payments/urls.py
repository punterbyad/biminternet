from django.urls import path
from . import views

app_name = 'payments'

urlpatterns = [
    path('initiate/', views.initiate_payment, name='initiate'),
    path('status/<str:reference>/', views.transaction_status, name='status'),
    path('callback/', views.momo_callback, name='callback'),
]
