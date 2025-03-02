from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from allauth.socialaccount.models import SocialAccount
from posts.singletons.logger_singleton import LoggerSingleton
from rest_framework_simplejwt.tokens import RefreshToken
import random
import string

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Enhanced adapter for handling Google OAuth account creation and linking
    - Handles duplicate email checks
    - Links Google accounts to existing users
    - Manages user creation
    - Includes comprehensive error handling and logging
    """
    def pre_social_login(self, request, sociallogin):
        logger = LoggerSingleton().get_logger()
        
        try:
            if not sociallogin.is_existing:
                email = sociallogin.email
                if email:
                    try:
                        # Check for existing user with same email
                        user = User.objects.get(email=email)
                        
                        # Check if user already has a different social account
                        if SocialAccount.objects.filter(user=user).exists():
                            logger.warning(f"Duplicate account attempt with email {email}")
                            raise ValidationError("Email already associated with another account")
                            
                        # Link existing account with Google
                        sociallogin.connect(request, user)
                        logger.info(f"Linked Google account to existing user {email}")
                        
                    except User.DoesNotExist:
                        # New user will be created
                        pass
                    except ValidationError as e:
                        logger.error(f"Account linking failed for {email}: {str(e)}")
                        raise
                        
        except Exception as e:
            logger.error(f"Error in pre_social_login: {str(e)}")
            raise

    def save_user(self, request, sociallogin, form=None):
        logger = LoggerSingleton().get_logger()
        try:
            user = super().save_user(request, sociallogin, form)
            logger.info(f"Successfully created new user from Google login: {user.email}")
            return user
        except Exception as e:
            logger.error(f"Failed to create user from Google login: {str(e)}")
            raise