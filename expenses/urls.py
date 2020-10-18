from django.urls import path
from . import views

urlpatterns = [
    path('', views.ExenseListAPIView.as_view(), name='expenses'),
    path('<int:id>',views.ExenseDetailAPIView.as_view(), name='expenses')
]