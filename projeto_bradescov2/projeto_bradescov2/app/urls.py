from django.urls import path
from .views import RegistroView, LoginView, ValoresReceberView, CustomLoginView


urlpatterns = [
    path('registro/', RegistroView.as_view()),
    path('login/', LoginView.as_view()),
    path('valores-a-receber/', ValoresReceberView.as_view()),

    # Pode matar tudo abaixo
    path('token/', CustomLoginView.as_view()), 
]
