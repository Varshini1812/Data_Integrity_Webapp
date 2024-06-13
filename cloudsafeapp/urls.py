from django.urls import path
from . import views

urlpatterns = [
    path("", views.login_view, name="login"),
    path("register/", views.register_view, name="register"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("dashboard/upload", views.upload_view, name="upload"),
    path("dashboard/querydata/", views.querydata_view, name="querydata"),
    path("activate_tpa/", views.activate_tpa_view, name="activate_tpa"),
    path("dashboard/fetch", views.fetch_view, name="fetch"),
    path(
        "dashboard/fetch/<str:file_id>",
        views.fetch_file_view,
        name="fetch_file",
    ),
    path('delete_file/<str:file_id>/', views.delete_view, name='delete_file'),
    path('verification-results/', views.verification_results_view, name='verification_results'),
    path('task-history/', views.task_history_view, name='task_history'),
    
]

handler404 = "cloudsafeapp.views.custom_404_view"