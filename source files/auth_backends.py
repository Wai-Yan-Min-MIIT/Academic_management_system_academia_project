from django.contrib.auth.backends import ModelBackend
import argon2
from .models import MIITUsers

class MIITUserBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):
        try: 
            print(username, password)
            user = MIITUsers.objects.get(username=username)
            print(f'Test {user}')
            if user.check_password(password):
                return user
        except MIITUsers.DoesNotExist:
            return None
        
        except argon2.exceptions.VerifyMismatchError:
            return None
        

    
    def user_can_authenticate(self, user):
        return True