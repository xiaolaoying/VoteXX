from django.db import models


# Create your models here.


class Flag(models.Model):
    sid = models.AutoField(primary_key=True)
    enc_data = models.BigIntegerField()
    op_time = models.DateField(auto_now_add=True)
