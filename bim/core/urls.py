from django.urls import path
from . import views
from django.urls import re_path

urlpatterns = [
    # Home
    path('', views.home, name='home'),

    # Dashboard
    path('dashboard/', views.dashboard_index, name='dashboard'),
    
    # Transactions
    path('transactions/', views.transactions_index, name='transactions.index'),
    # Backwards-compatible alias: some templates use 'transactions_index'
    path('transactions/', views.transactions_index, name='transactions_index'),
    path('transactions/export/excel/', views.transactions_export_excel, name='transactions.export.excel'),
    path('transactions/export/pdf/', views.transactions_export_pdf, name='transactions.export.pdf'),
    # Backwards-compatible aliases (underscore style)
    path('transactions/export/excel/', views.transactions_export_excel, name='transactions_export_excel'),
    path('transactions/export/pdf/', views.transactions_export_pdf, name='transactions_export_pdf'),

    # Routers CRUD
    path('routers/', views.router_index, name='routers.index'),
    path('routers/create/', views.router_create, name='routers.create'),
    path('routers/store/', views.router_store, name='routers.store'),  # POST
    # Fallback route for legacy frontend expecting /routers/json/... paths
    re_path(r'^routers/json/(?P<filename>.*)$', views.routers_json, name='routers.json'),
    path('routers/<uuid:router_id>/', views.router_show, name='routers.show'),
    path('routers/<uuid:router_id>/edit/', views.router_edit, name='routers.edit'),
    path('routers/<uuid:router_id>/connect/', views.router_connect_to_router, name='routers.connect'),
    path('routers/<uuid:router_id>/update/', views.router_update, name='routers.update'),  # POST update
    path('routers/<uuid:router_id>/delete/', views.router_destroy, name='routers.destroy'),  # POST delete

    # Hotspot Servers
    path('routers/<uuid:router_id>/hotspots/', views.router_list_all_hotspot_servers, name='hotspots.index'),

    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/', views.router_list_hotspot_users, name='hotspots.users'),
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/edit/', views.router_edit_hotspot_server, name='hotspots.edit'),
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/', views.router_update_hotspot_server, name='hotspots.update'),  # PUT
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/', views.router_store_hotspot_user, name='hotspots.users.store'),  # POST
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/create/', views.router_create_hotspot_user, name='hotspots.users.create'),
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>/', views.router_update_hotspot_user, name='hotspots.users.update'),  # PUT
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>/', views.router_delete_hotspot_user, name='hotspots.users.delete'),  # DELETE
    #path('routers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>/edit/', views.router_edit_hotspot_user, name='hotspots.users.edit'),

    # Hotspot Vouchers Management
    path('vouchers/', views.voucher_list_routers, name='vouchers.index'),
    path('vouchers/<uuid:router_id>/hotspots/', views.voucher_list_all_hotspot_servers, name='voucherspots.index'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/', views.voucher_list_hotspot_users, name='voucherspots.users'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>/edit', views.voucher_edit_hotspot_user, name='voucherspots.users.edit'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>', views.voucher_update_hotspot_user, name='voucherspots.users.update'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>/disable', views.voucher_disable_hotspot_user, name='voucherspots.users.disable'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/<str:user_id>/delete', views.voucher_delete_hotspot_user, name='voucherspots.users.delete'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/users/create', views.voucher_create_hotspot_user, name='voucherspots.users.create'),
    path('vouchers/<uuid:router_id>/hotspots/<str:hotspot_id>/users', views.voucher_store_hotspot_user, name='voucherspots.users.store'),

    # Package/Hotspot/Profile management (Laravel route names and patterns)
    path('packages/', views.package_list_routers, name='packages.index'),
    path('packages/<uuid:router_id>/hotspots/', views.package_list_all_hotspot_servers, name='packagespots.index'),
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles', views.package_get_all_hotspot_user_profiles, name='packageprofiles.index'),
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/create', views.package_create_hotspot_user_profile, name='packagespots.create'),
    # Make the store route unique so POST requests are routed to the store view
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/store', views.package_store_hotspot_user_profile, name='packagespots.store'),
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/<str:profile_id>', views.package_get_hotspot_user_profile, name='packagespots.show'),
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/<str:profile_id>/edit', views.package_edit_hotspot_user_profile, name='packagespots.edit'),
    # Use an explicit update path so POSTs map reliably to the update view
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/<str:profile_id>/update', views.package_update_hotspot_user_profile, name='packagespots.update'),
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/<str:profile_id>/disable', views.package_get_hotspot_user_profile, name='packagespots.disable'),  # Placeholder, implement disable logic
    path('packages/<uuid:router_id>/hotspots/<str:hotspot_id>/profiles/packages/profiles/<str:profile_id>/delete', views.package_delete_hotspot_user_profile, name='packagespots.delete'),

    # Notifications
    path('notifications/', views.notification_index, name='notifications.index'),
    path('notifications/count/', views.notification_count, name='notifications.count'),
    
    # Withdrawal
    path('withdraw/', views.withdraw_index, name='withdraw.index'),
    path('withdraw/<uuid:router_id>/create/', views.withdraw_create, name='withdraw.create'),
    path('withdraw/<uuid:router_id>/store/', views.withdraw_store, name='withdraw.store'),
]

