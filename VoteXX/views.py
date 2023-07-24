from django.shortcuts import render, HttpResponse, redirect
import json
import sqlite3
# Create your views here.



def toLogin_view(request):
    return render(request, 'login.html')

def election_view(request):

    from VoteXX import models

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        # res = {"user": None, "msg": None}
        s = request.POST.get("sid")
        e = request.POST.get("enc_data")
        o = request.POST.get("op_time")
        print(request.POST)

        dic = {'sid': s, 'enc_data': e, 'op_time': o}
        models.Flag.objects.create(**dic)
        # conn = sqlite3.connect("django.db")
        # c = conn.cursor()
        # sql1 = '''
        #     insert into VoteXX_flag(sid, enc_data, op_time)
        # '''
        # c.execute(sql1)
        # conn.commit()
        # conn.close()
    return render(request, 'election_page.html')

