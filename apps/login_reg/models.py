# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
import bcrypt
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Create your models here.

class UserManager(models.Manager):
    def validate_and_create_user(self, form):
        errors = []

        #first name validation
        if form['first_name'] == "": 
            errors.append('First name field cannot be blank')
        elif len(form['first_name']) < 2:
            errors.append('First name field must be at least 2 characters long')
        
        #last name validation
        if form['last_name'] == "":
            errors.append('Last name field cannot be blank')
        elif len(form['last_name']) < 2:
            errors.append('Last name field must be at least 2 characters long')


        #password validation
        if form['password'] == "": 
            errors.append('Password required')
        elif len(form['password']) < 8: #validate for length
            errors.append('Password must be at least 8 characters long')
        elif form['password'] != form['confirm']:
            errors.append('Password and confirm must match')

        #email validation
        if form['email'] == "": 
            errors.append('Email required')
        elif not EMAIL_REGEX.match(form['email']): #validate for email uniqueness
            errors.append('Email must be valid')
        elif len(form['email']) < 4: #validate for length
            errors.append('Email must valid')

        #Ex.checking for pre-existing Username
        # username_list = self.filter(username=form['username'])
        # if len(username_list) > 0:
        # errors.append('Username already in use')

        #checking db for pre-existing email
        try:
            email_list = self.get(email=form['email'])
            errors.append('Email already in use')
            return (False, errors)
        except:
            if len(errors) > 0:
                return (False, errors)
            else:
                pw_hash = bcrypt.hashpw(form['password'].encode(), bcrypt.gensalt())
                user = self.create(first_name=form['first_name'], last_name=form['last_name'], email=form['email'], pw_hash=pw_hash)
                return (True, user)

    def validate_login(self, form):
        errors = []

        try:
            user = self.get(email=form['email'])
            #log user in
            if bcrypt.checkpw(form['password'].encode(), user.pw_hash.encode()):
                return (True, user)
            else: #check if password matches
                errors.append('Incorrect email or password')
                return (False, errors)
        except: #email doesn't exist
            errors.append('Incorrect email or password')
            return (False, errors)

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    pw_hash = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    
    objects = UserManager()

    def __str__(self):
        output = "<User object:{} {}>".format(self.first_name, self.last_name)
        return output

  