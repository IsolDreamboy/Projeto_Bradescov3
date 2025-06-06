from django.db import models


class Client(models.Model):
    nome = models.CharField(max_length=100)
    cpf = models.CharField(max_length=11, unique=True)
    email = models.EmailField(unique=True)
    nascimento = models.DateField()
    senha = models.CharField(max_length=100)
    valor_a_receber = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)




    def __str__(self):
        return self.nome

