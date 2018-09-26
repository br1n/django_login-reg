from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
from django.contrib.auth import logout

# Create your views here.

def index(req):
    if 'user_id' in req.session:
        return redirect('/success')

    else:
        return render(req, 'index.html')


def process(req):
    if req.method != 'POST': 
        return redirect('/')

    valid, response = User.objects.validate_and_create_user(req.POST)
    if valid:
        req.session['user_id'] =response.id
        return redirect('/success')
    else:
        for error in response:
            messages.error(req, error)
    return redirect('/')


def login(req):
    if req.method != 'POST':
        return redirect('/')

    valid, response = User.objects.validate_login(req.POST)
    if valid == False:
        for error in response:
            messages.error(req, error)
        return redirect('/')
    else:
        req.session['user_id'] = response.id
        return redirect('/success')

def success(req):

    if not 'user_id' in req.session:
        return redirect('/')
    user = User.objects.get(id=req.session['user_id'])
    context = {
        'user':user
    }
    return render(req, 'success.html', context)

    if 'user_id' in req.session:
        return redirect('/success')
  
def logout(req):
    req.session.clear()
    return redirect('/')
