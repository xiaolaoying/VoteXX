from django.shortcuts import render
from BulletinBoard import models
# Create your views here.

def BB(request):
    # test BB display
    # models.BB_data.objects.create(public_key='123456', key_type=True)
    # models.BB_data.objects.create(public_key='234567', key_type=False)
    # models.BB_data.objects.create(public_key='345678', key_type=True)
    # models.BB_data.objects.create(public_key='456789', key_type=False)
    #
    # obj = models.BB_data(public_key='987654', key_type=True)
    # obj.save()

    list = models.BB_data.objects.all()

    return render(request, 'BB/BB_page.html', locals())

