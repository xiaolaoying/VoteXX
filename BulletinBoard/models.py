from django.db import models

# Create your models here.

class BB_data(models.Model):

    # the data on the Bulletin Board
    # key_type = False if it's a pkNo, otherwise True for pkYes
    public_key = models.BigIntegerField(primary_key=True)
    key_type = models.BooleanField()
