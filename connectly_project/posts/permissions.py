from rest_framework.permissions import BasePermission
from django.db.models import Q

class IsPostAuthor(BasePermission):
    """
    Custom permission to allow only the author of a post to access or modify it.
    """
    def has_object_permission(self, request, view, obj):
        """
        Check if the requesting user is the author of the post.
        
        Returns True if the user is the author, False otherwise.
        """
        return obj.author == request.user  # Allow access if the post's author matches the request user

class IsCommentAuthor(BasePermission):
    """
    Custom permission to only allow the author of a comment to edit or delete it.
    """
    def has_object_permission(self, request, view, obj):
        # Check if the request user is the author of the comment
        return obj.author == request.user

class IsAdminOrModerator(BasePermission):
    """
    Permission to check if user is an admin or moderator.
    """
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        # Check if user has staff privileges
        if request.user.is_staff:
            return True
            
        # Check if user has a profile with admin or moderator role
        if hasattr(request.user, 'profile'):
            return request.user.profile.role in ['admin', 'moderator']
            
        return False

class HasPostVisibilityPermission(BasePermission):
    """
    Permission to check if user can view a post based on privacy settings.
    """
    def has_object_permission(self, request, view, obj):
        # Admin and moderators can access any post
        if request.user.is_staff:
            return True
            
        if hasattr(request.user, 'profile') and request.user.profile.role in ['admin', 'moderator']:
            return True
            
        # Author can always access their own post
        if obj.author == request.user:
            return True
            
        # Check privacy settings
        if obj.privacy == 'public':
            return True
        elif obj.privacy == 'followers':
            # Check if requesting user follows the author
            if hasattr(obj.author, 'profile'):
                return request.user in obj.author.profile.followers.all()
        
        # Private posts only accessible to author (already handled above)
        return False