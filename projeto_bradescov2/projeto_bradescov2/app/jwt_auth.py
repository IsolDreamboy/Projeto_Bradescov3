from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import Client
from django.contrib.auth.hashers import check_password
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    cpf = serializers.CharField()
    senha = serializers.CharField()

    def validate(self, attrs):
        cpf = attrs.get("cpf")
        senha = attrs.get("senha")

        try:
            client = Client.objects.get(cpf=cpf)
        except Client.DoesNotExist:
            raise serializers.ValidationError("CPF não encontrado.")

        if not check_password(senha, client.senha):
            raise serializers.ValidationError("Senha incorreta.")

        # Cria o token com dados extras
        refresh = RefreshToken.for_user(client)
        refresh["cpf"] = client.cpf
        refresh["nascimento"] = str(client.nascimento)
        refresh["user_id"] = client.id

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "nome": client.nome,
            "cpf": client.cpf,
            "email": client.email
        }

        return data