from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.urls import reverse
from django.views.decorators import csrf
from AseModel.models import ScanPort
from django.contrib.auth.decorators import login_required


# @login_required(login_url='/ase/login/')
def front_index(request):
    context = {'hello': 'Hello World!'}
    return render(request, 'index.html')

