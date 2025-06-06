from rest_framework import serializers
from .models import Client
from rest_framework_simplejwt.views import TokenObtainPairView
from .jwt_auth import CustomTokenObtainPairSerializer


class CustomLoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = '__all__'

    def validate_email(self, value):
        if Client.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email já está em uso.")
        return value

    def validate_cpf(self, value):
        if Client.objects.filter(cpf=value).exists():
            raise serializers.ValidationError("CPF já está em uso.")
        return value
