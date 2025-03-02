from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import User
from .models import Profile, Post, Comment
import random
import string

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Signal handler that automatically creates a Profile when a User is created.
    
    Args:
        sender: The model class (User)
        instance: The actual User instance being saved
        created: Boolean flag indicating if this is a new User
        kwargs: Additional keyword arguments
        
    This ensures every user has an associated profile without requiring manual creation.
    """
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Signal handler that saves a User's Profile when the User is updated.
    
    Args:
        sender: The model class (User)
        instance: The actual User instance being saved
        kwargs: Additional keyword arguments
        
    Ensures profile changes are persisted when user model is updated.
    """
    # Check if profile exists to prevent errors
    if hasattr(instance, 'profile'):
        instance.profile.save()


@receiver(post_save, sender=Post)
def update_profile_posts_count(sender, instance, created, **kwargs):
    """
    Signal handler that updates the posts_count in a user's Profile 
    when a new Post is created.
    
    Args:
        sender: The model class (Post)
        instance: The actual Post instance being saved
        created: Boolean flag indicating if this is a new Post
        kwargs: Additional keyword arguments
        
    Keeps profile statistics in sync with actual post count.
    """
    if created:
        profile = instance.author.profile
        profile.update_counts()


@receiver(post_delete, sender=Post)
def update_profile_posts_count_on_delete(sender, instance, **kwargs):
    """
    Signal handler that updates the posts_count in a user's Profile
    when a Post is deleted.
    
    Args:
        sender: The model class (Post)
        instance: The actual Post instance being deleted
        kwargs: Additional keyword arguments
        
    Ensures profile statistics remain accurate when posts are removed.
    """
    profile = instance.author.profile
    profile.update_counts()


@receiver(post_save, sender=SocialAccount)
def handle_social_account_creation(sender, instance, created, **kwargs):
    """
    Signal handler that processes newly created social accounts.
    
    This handler:
    1. Creates or updates a Profile for social users
    2. Handles profile picture import from social provider
    3. Generates a unique username based on social account info
    
    Args:
        sender: The model class (SocialAccount)
        instance: The actual SocialAccount instance being saved
        created: Boolean flag indicating if this is a new SocialAccount
        kwargs: Additional keyword arguments
        
    Ensures smooth onboarding for users who sign up with social providers.
    """
    if created and instance.provider == 'google':
        user = instance.user
        
        # Update or create profile
        profile, profile_created = Profile.objects.get_or_create(user=user)
        
        # Import profile picture from Google if available
        if 'picture' in instance.extra_data:
            profile_pic_url = instance.extra_data['picture']
            # Note: Implementation needed to download and save the image
            # profile.profile_picture = ... (download and save logic)
            # profile.save()
        
        # Generate unique username if needed
        if not user.username or '@' in user.username:
            # Try to use first+last name if available
            if user.first_name and user.last_name:
                username_base = f"{user.first_name.lower()}_{user.last_name.lower()}"
            else:
                # Fall back to email prefix
                email_name = user.email.split('@')[0]
                username_base = email_name
            
            # Ensure username uniqueness
            username = username_base
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{username_base}{counter}"
                counter += 1
            
            # Save the new username
            user.username = username
            user.save()