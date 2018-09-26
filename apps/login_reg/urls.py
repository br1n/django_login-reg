from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name="index"), 
    url(r'^process/$', views.process, name="process"), #aka register
    url(r'^login/$', views.login, name="login"),
    url(r'^success/$', views.success, name="success"), #aka show
    url(r'^logout$', views.logout, name="logout"),
]

#Full CRUD operation
# urlpatterns = [
#     url(r'^$', views.index, name="index"),
#     url(r'^new/$', views.new, name="new"),
#     url(r'^create/$', views.create, name="create"),
#     url(r'^(?P<user_id>\d+)/show/$', views.show, name="show"),
#     url(r'^(?P<user_id>\d+)/edit/$', views.edit, name="edit"),
#     url(r'^(?P<user_id>\d+)/update/$', views.update, name="update"),
#     url(r'^(?P<user_id>\d+)/delete/$', views.delete, name="delete"),
#     url(r'^login/$', views.login, name="login"),
#     ]