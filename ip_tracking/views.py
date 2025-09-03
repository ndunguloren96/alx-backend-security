# alx-backend-security/ip_tracking/views.py

from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.http import HttpResponseBadRequest
from ratelimit.decorators import ratelimit
from django.views.decorators.http import require_POST
from django.contrib import messages

@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@ratelimit(key='user', rate='10/m', method='POST', block=True)
@require_POST
def login_view(request):
    """
    A view to handle user login, with rate limiting applied.
    """
    if request.user.is_authenticated:
        return render(request, 'some_template.html', {'message': 'You are already logged in.'})

    username = request.POST.get('username')
    password = request.POST.get('password')

    if not username or not password:
        messages.error(request, 'Both username and password are required.')
        return HttpResponseBadRequest("Invalid request.")

    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        login(request, user)
        return render(request, 'some_template.html', {'message': 'Login successful!'})
    else:
        messages.error(request, 'Invalid credentials.')
        return render(request, 'some_template.html', {'message': 'Invalid credentials.'})

# The decorator for anonymous users is slightly different.
# It can also be applied based on the 'anon' key.
# For example, on a different view or with a more complex decorator setup.
# The `django-ratelimit` library handles the authenticated vs. anonymous distinction by default
# when using 'ip' and 'user' keys. `request.user.is_authenticated` is used to differentiate.
