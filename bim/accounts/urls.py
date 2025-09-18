from django.urls import path
from .views import (
    SignUpView, ProfileEditView, TOTPSetupView, LoginView, LoginTOTPView,
    ProfileTotpWizardView, LostPhoneStartView, LostPhoneVerifyView,
    SendOTPView, VerifyOTPView, throttle_status,
    sumsub_webhook, kyc_results_list, logout_view, dashboard_index,
    accept_invitation, CustomLoginView, invite_account_member, access_management,
    access_redirect, cancel_invitation,
)
from .views import client_log
from .kyc_views import kyc_start, kyc_webhook_sumsub, kyc_webhook_veriff

app_name = 'accounts'

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('profile/edit/', ProfileEditView.as_view(), name='profile_edit'),
    path('profile-setup/<str:step>/', ProfileTotpWizardView.as_view(), name='profile_wizard'),
    path('totp/setup/', TOTPSetupView.as_view(), name='totp_setup'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/totp/', LoginTOTPView.as_view(), name='login_totp'),
    path('send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('lost-phone/', LostPhoneStartView.as_view(), name='lost_phone_start'),
    path('lost-phone/verify/', LostPhoneVerifyView.as_view(), name='lost_phone_verify'),
    path('logout/', logout_view, name='logout'),
    path('throttle-status/', throttle_status, name='throttle_status'),
    path('kyc/start/', kyc_start, name='kyc_start'),
    path('kyc/webhook/sumsub/', kyc_webhook_sumsub, name='kyc_webhook_sumsub'),
    path('kyc/webhook/veriff/', kyc_webhook_veriff, name='kyc_webhook_veriff'),
    path('dashboard/', dashboard_index, name='dashboard_home'),
    path('webhooks/sumsub/', sumsub_webhook, name='subsum_webhook'),
    path('kyc-results/', kyc_results_list, name='kyc_results_list'),
    path('accept-invitation/<int:membership_id>/', accept_invitation, name='accept_invitation'),
    path('<uuid:account_id>/invite/', invite_account_member, name='invite_account_member'),
    path('<uuid:account_id>/access/', access_management, name='access_management'),
    path('access/', access_redirect, name='access_redirect'),
    path('cancel-invitation/<int:membership_id>/', cancel_invitation, name='cancel_invitation'),
    path('client-log/', client_log, name='client_log'),
]
