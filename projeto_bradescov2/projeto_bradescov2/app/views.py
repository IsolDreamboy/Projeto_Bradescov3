from django.shortcuts import render
import requests
import jwt
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Client
from .serializers import ClientSerializer
from django.contrib.auth.hashers import make_password, check_password
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from .jwt_auth import CustomTokenObtainPairSerializer
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken

# Endpoint de registro
class RegistroView(APIView):
    def post(self, request):
        print("DADOS RECEBIDOS:", request.data)
        data = request.data.copy()
        data['senha'] = make_password(data['senha'])  # Criptografa a senha
        serializer = ClientSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({'mensagem': 'Usuário registrado com sucesso!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Endpoint de login
class LoginView(APIView):
    def post(self, request):
        cpf = request.data.get('cpf')
        senha = request.data.get('senha')

        try:
            client = Client.objects.get(cpf=cpf)
            dta_nasc = client.nascimento

            if check_password(senha, client.senha):
                refresh = RefreshToken.for_user(client)

                # Adiciona informações extras no token
                refresh['cpf'] = cpf
                refresh['nascimento'] = str(dta_nasc)

                return Response({
                    'mensagem': 'Login realizado com sucesso!',
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                })

            return Response({'erro': 'Senha incorreta'}, status=status.HTTP_401_UNAUTHORIZED)

        except Client.DoesNotExist:
            return Response({'erro': 'CPF não encontrado'}, status=status.HTTP_404_NOT_FOUND)
        

# Endpoint alyson


class ValoresReceberView(APIView):
    def post(self, request):
        print("CHAMADA OK - HEADERS:", request.headers)

        # Pega o token do cabeçalho Authorization
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return Response({'erro': 'Token ausente ou mal formatado'}, status=401)

        token = auth_header.replace('Bearer ', '')

        try:
            # Decodifica o token com a SECRET_KEY
            decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            cpf = decoded.get('cpf')
            nascimento = decoded.get('nascimento')

            # Se não tem CPF/nascimento no token, busca via user_id
            if not (cpf and nascimento):
                user_id = decoded.get('user_id')
                if not user_id:
                    return Response({'erro': 'Token inválido. Sem user_id.'}, status=401)

                try:
                    client = Client.objects.get(id=user_id)
                    cpf = client.cpf
                    nascimento = str(client.nascimento)
                except Client.DoesNotExist:
                    return Response({'erro': 'Usuário não encontrado.'}, status=404)

            # Envia os dados para a API do Alyson
            params = {
                "cpf": cpf,
                "dta_nasc": nascimento
            }

            resposta = requests.get(
                "http://127.0.0.1:8090/valores-a-receber/consulta",
                params=params,
                timeout=5
            )

            if resposta.status_code == 200:
                return Response(resposta.json(), status=200)
            else:
                return Response({
                    'erro': 'Erro ao chamar a API externa',
                    'detalhes': resposta.text
                }, status=502)

        except jwt.ExpiredSignatureError:
            return Response({'erro': 'Token expirado'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'erro': 'Token inválido'}, status=401)
        except Exception as e:
            return Response({'erro': f'Erro inesperado: {str(e)}'}, status=500)
#tirar
class CustomLoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


