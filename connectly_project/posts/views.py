# Python Standard Library
import random
import string
import time

# Django imports
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.shortcuts import render
from django.db.models import Count, Q, F
from django.core.cache import cache
from django.utils import timezone

# Third-party packages
from allauth.socialaccount.models import SocialAccount
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from datetime import timedelta

# Local imports
from .models import Post, Comment, Like, Profile
from .permissions import IsPostAuthor, IsCommentAuthor, HasPostVisibilityPermission
from .serializers import (
    UserSerializer,
    PostSerializer,
    CommentSerializer,
    LikeSerializer,
    ProfileSerializer
)
from posts.factories.post_factory import PostFactory
from posts.singletons.config_manager import ConfigManager
from posts.singletons.logger_singleton import LoggerSingleton

    
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token view that returns user data along with tokens
    """
    def post(self, request, *args, **kwargs):
        # Get tokens using parent class
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Add user data to response
            user = authenticate(
                username=request.data.get('username'),
                password=request.data.get('password')
            )
            user_data = UserSerializer(user).data
            response.data['user'] = user_data
            
        return response


class UserLoginView(APIView):
    """
    Enhanced login view with JWT tokens and user data
    """
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Login successful',
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                },
                'user': UserSerializer(user).data
            })
        
        return Response(
            {"error": "Invalid credentials"}, 
            status=status.HTTP_401_UNAUTHORIZED
        )

class UserLogoutView(APIView):
    """
    Logout view that blacklists the refresh token
    """
    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Successfully logged out"}, 
                status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"error": "Invalid token"}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class UserCreate(APIView):
    """
    User Registration Endpoint
    - Open registration with basic validations
    - Prevents duplicate usernames/emails
    - Security: Basic input validation
    - Permissions: Allows anyone to create account
    """

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        # Validate required fields
        if not username or not password:
            return Response(
                {'error': 'Username and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for existing users
        if User.objects.filter(username=username).exists():
            return Response(
                {'error': 'Username already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'Email already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Create user with hashed password
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )

            # Generate a token for the newly created user
            refresh = RefreshToken.for_user(user)

            # Return user data along with the generated token
            return Response({
                "message": "User created successfully",
                 "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token)
                }
            }, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserListView(APIView):
    """
    User Listing Endpoint
    - Token authentication required
    - Admin-only access
    - Security: Restricts user list to staff members
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Additional check for admin privileges
        if not request.user.is_staff:
            raise PermissionDenied('Admin access required.')
        
        # Retrieve and return user list
        users = User.objects.all()
        user_data = [
            {"id": user.id, "username": user.username, "email": user.email} 
            for user in users
        ]
        return Response(user_data, status=status.HTTP_200_OK)


class UserDetailView(APIView):
    """
    User Detail Management Endpoint
    - Token authentication required
    - Supports retrieve/update/delete
    - Security: 
      * Authenticated users can view their own details
      * Only admin can modify/delete users
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        # Retrieve specific user details
        try:
            user = User.objects.get(id=pk)
            return Response({
                'id': user.id,
                'username': user.username,
                'email': user.email
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            raise NotFound('User not found')

    def put(self, request, pk):
        # Update user (admin only)
        if not request.user.is_staff:
            raise PermissionDenied('Admin access required.')

        try:
            user = User.objects.get(id=pk)
            serializer = UserSerializer(user, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            raise NotFound('User not found')

    def delete(self, request, pk):
        # Delete user (admin only)
        if not request.user.is_staff:
            raise PermissionDenied('Admin access required.')

        try:
            user = User.objects.get(id=pk)
            user.delete()
            return Response(
                {"message": "User deleted successfully."}, 
                status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            raise NotFound('User not found')


class ProtectedView(APIView):
    """
    Authentication Verification Endpoint
    - Requires valid token
    - Confirms user is authenticated
    - Used for testing/verifying authentication
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Authenticated!"})


class PostListCreate(APIView):
    """
    Post Management Endpoint with privacy filters
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get current user
        user = request.user
        
        # Base query
        base_query = Post.objects.all()
        
        # If not admin/moderator, apply privacy filters
        if not (user.is_staff or (hasattr(user, 'profile') and user.profile.role in ['admin', 'moderator'])):
            # Include user's own posts
            privacy_filter = Q(author=user)
            
            # Include public posts
            privacy_filter |= Q(privacy='public')
            
            # Include followers-only posts from users the current user follows
            following_ids = []
            if hasattr(user, 'following'):
                following_ids = user.following.values_list('id', flat=True)
            
            privacy_filter |= Q(privacy='followers', author_id__in=following_ids)
            
            # Apply the filter
            base_query = base_query.filter(privacy_filter)
        
        posts = base_query.order_by('-created_at')
        serializer = PostSerializer(posts, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        # Validate post content
        content = request.data.get('content', '').strip()
        if not content:
            return Response(
                {'error': 'Post content cannot be empty.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate post type
        post_type = request.data.get('post_type', '')
        if post_type not in dict(Post.POST_TYPES):
            return Response(
                {'error': 'Invalid post type.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare metadata
        metadata = request.data.get('metadata', {})
        metadata['author_id'] = request.user.id

        try:
            post = PostFactory.create_post(
                post_type,
                request.data['title'],
                content,
                metadata
            )
            
            # Set privacy if provided
            privacy = request.data.get('privacy', 'public')
            if privacy in dict(Post.PRIVACY_CHOICES).keys():
                post.privacy = privacy
                post.save()
                
            return Response(
                PostSerializer(post, context={'request': request}).data,
                status=status.HTTP_201_CREATED
            )
        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )



class PostDetailView(APIView):
    """
    Individual Post Management Endpoint
    - Token authentication required
    - Supports retrieve/update/delete
    - Security:
      * Only authenticated users can access
      * Only post author can modify/delete
      * Validates post modifications
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, HasPostVisibilityPermission]

    def get(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            self.check_object_permissions(request, post)
            return Response(
                PostSerializer(post, context={'request': request}).data, 
                status=status.HTTP_200_OK
            )
        except Post.DoesNotExist:
            raise NotFound('Post not found')

    def put(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            
            # Only author can update the post
            if post.author != request.user:
                raise PermissionDenied('You do not have permission to edit this post')

            content = request.data.get('content', '').strip()
            if not content:
                return Response(
                    {'error': 'Post content cannot be empty.'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = PostSerializer(post, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    serializer.data, 
                    status=status.HTTP_200_OK
                )
            
            return Response(
                serializer.errors, 
                status=status.HTTP_400_BAD_REQUEST
            )
        except Post.DoesNotExist:
            raise NotFound('Post not found')

    def delete(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
            
            # Author or admin/moderator can delete posts
            if post.author != request.user and not (
                request.user.is_staff or 
                (hasattr(request.user, 'profile') and request.user.profile.role in ['admin', 'moderator'])
            ):
                raise PermissionDenied('You do not have permission to delete this post')

            post.delete()
            return Response(
                {"message": "Post deleted successfully."}, 
                status=status.HTTP_200_OK
            )
        except Post.DoesNotExist:
            raise NotFound('Post not found')
        

class CommentListCreate(APIView):
    """
    Comment Management Endpoint
    - Token authentication required
    - Supports comment listing and creation
    - Security: 
        * Only authenticated users can create comments
        * Validates comment text
        * Automatically assigns comment author
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # List all comments
        comments = Comment.objects.all()
        return Response(
            CommentSerializer(comments, many=True).data,
            status=status.HTTP_200_OK
        )

    def post(self, request):
        request.data['author'] = request.user.id
        try:
            post = Post.objects.get(id=request.data.get('post'))
            serializer = CommentSerializer(
                data=request.data,
                context={'request': request}
            )
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Post.DoesNotExist:
            return Response(
                {'error': 'Post not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class CommentDetailView(APIView):
    """
    Individual Comment Management Endpoint
    - Token authentication required
    - Supports retrieve, update, and delete actions
    - Security: 
        * Only authenticated users can access
        * Only the comment author can update or delete their comment
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsCommentAuthor]

    def get(self, request, pk):
        # Retrieve specific comment
        try:
            comment = Comment.objects.get(pk=pk)
            self.check_object_permissions(request, comment)
            return Response(
                {"text": comment.text},
                status=status.HTTP_200_OK
            )
        except Comment.DoesNotExist:
            raise NotFound('Comment not found')

    def put(self, request, pk):
        try:
            comment = Comment.objects.get(pk=pk)
            self.check_object_permissions(request, comment)
            serializer = CommentSerializer(
                comment,
                data=request.data,
                partial=True
            )
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Comment.DoesNotExist:
            raise NotFound('Comment not found')

    def delete(self, request, pk):
        # Delete specific comment
        try:
            comment = Comment.objects.get(pk=pk)
            self.check_object_permissions(request, comment)
            comment.delete()
            return Response(
                {"message": "Comment deleted successfully."},
                status=status.HTTP_200_OK
            )
        except Comment.DoesNotExist:
            raise NotFound('Comment not found')
        

class PostCommentsView(APIView):
    """
    Get comments for a specific post with pagination and sorting
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, post_id):
        try:
            # Get post
            post = Post.objects.get(pk=post_id)
            
            # Get page parameters
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 10))
            
            # Get sort parameter and validate
            sort_by = request.query_params.get('sort', '-created_at')
            valid_sort_fields = ['created_at', '-created_at', 'likes_count', '-likes_count']
            
            if sort_by not in valid_sort_fields:
                sort_by = '-created_at'
            
            # Handle sorting with likes count annotation
            if sort_by.endswith('likes_count'):
                comments = Comment.objects.filter(post=post).annotate(
                    likes_count=Count('likes')
                ).order_by(sort_by)
            else:
                comments = Comment.objects.filter(post=post).order_by(sort_by)
            
            # Apply pagination
            start = (page - 1) * page_size
            end = start + page_size
            
            paginated_comments = comments[start:end]
            total_comments = comments.count()
            
            return Response({
                'comments': CommentSerializer(paginated_comments, many=True).data,
                'total': total_comments,
                'page': page,
                'total_pages': (total_comments + page_size - 1) // page_size,
                'sort_by': sort_by
            })
            
        except Post.DoesNotExist:
            raise NotFound('Post not found')
       
"""       
class SingletonTestView(APIView):
  
    Test Singleton behavior of the ConfigManager

    def get(self, request):
        # Retrieve the DEFAULT_PAGE_SIZE from the ConfigManager Singleton
        config = ConfigManager()
        default_page_size = config.get_setting("DEFAULT_PAGE_SIZE")
        return Response({"DEFAULT_PAGE_SIZE": default_page_size})
    """ 

class LikeView(APIView):
    """
    Like/Unlike Post Endpoint
    - Token authentication required
    - Supports like/unlike actions
    - Prevents duplicate likes
    - Prevents users from liking their own posts
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, post_id):
        try:
            post = Post.objects.get(pk=post_id)
            
            # Check if like already exists
            like = Like.objects.filter(user=request.user, post=post).first()
            
            if like:
                # Unlike if already liked
                like.delete()
                return Response({
                    "message": "Post unliked successfully",
                    "likes_count": post.likes.count()
                }, status=status.HTTP_200_OK)
            
            # Create new like
            like = Like(user=request.user, post=post)
            like.clean()  # Run validation
            like.save()
            
            return Response({
                "message": "Post liked successfully",
                "likes_count": post.likes.count()
            }, status=status.HTTP_201_CREATED)
            
        except Post.DoesNotExist:
            return Response(
                {"error": "Post not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except ValidationError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class PostLikesView(APIView):
    """
    Post Likes List Endpoint
    - Get list of users who liked a post
    - Token authentication required
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, post_id):
        try:
            post = Post.objects.get(pk=post_id)
            likes = Like.objects.filter(post=post)
            serializer = LikeSerializer(likes, many=True)
            
            return Response({
                "likes_count": likes.count(),
                "likes": serializer.data
            }, status=status.HTTP_200_OK)
            
        except Post.DoesNotExist:
            return Response(
                {"error": "Post not found"},
                status=status.HTTP_404_NOT_FOUND
            )

class ConfigView(APIView):
    """Configuration management endpoint"""
    
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        config = ConfigManager()
        return Response({
            "DEFAULT_PAGE_SIZE": config.get_setting("DEFAULT_PAGE_SIZE")
        })

class GoogleLoginSuccessView(APIView):
    """
    Handle successful Google OAuth login
    Converts social authentication to JWT tokens
    Handles various error scenarios with detailed responses
    """
    def get(self, request):
        logger = LoggerSingleton().get_logger()
        logger.info("Starting Google login success flow")

        try:
            # Error 1: User not authenticated
            # This could happen if the OAuth flow was interrupted or failed
            if not request.user.is_authenticated:
                logger.error("Unauthenticated access attempt to Google login success")
                return Response({
                    "error": "Authentication required",
                    "code": "authentication_required",
                    "message": "User authentication is required for this endpoint"
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Error 2: No Google account linked
            # This could happen if the social account was deleted or not properly created
            try:
                social_account = SocialAccount.objects.get(
                    user=request.user,
                    provider='google'
                )
            except SocialAccount.DoesNotExist:
                logger.error(f"No Google account found for user {request.user.email}")
                return Response({
                    "error": "No Google account linked",
                    "code": "no_social_account",
                    "message": "No Google account is linked to this user"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Error 3: Token expiration check
            # Checks if the Google OAuth token has expired
            if hasattr(social_account, 'extra_data') and 'expires_at' in social_account.extra_data:
                if social_account.extra_data['expires_at'] < time.time():
                    logger.error(f"Expired Google token for user {request.user.email}")
                    return Response({
                        "error": "Google token expired",
                        "code": "token_expired",
                        "message": "Google authentication token has expired, please login again"
                    }, status=status.HTTP_401_UNAUTHORIZED)

            # Error 4: JWT token generation failure
            # This could happen due to user model issues or system errors
            try:
                refresh = RefreshToken.for_user(request.user)
            except Exception as e:
                logger.error(f"JWT generation failed for user {request.user.email}: {str(e)}")
                return Response({
                    "error": "Token generation failed",
                    "code": "token_generation_failed",
                    "message": "Failed to generate authentication tokens"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Error 5: Missing required user data
            # Ensures all required user data is present
            if not all([request.user.username, request.user.email]):
                logger.error(f"Incomplete user data for {request.user.id}")
                return Response({
                    "error": "Incomplete user data",
                    "code": "incomplete_user_data",
                    "message": "User profile is missing required information"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Determine if this is a new account
            is_new_account = social_account.date_joined == social_account.last_login

            # Collect user data for response
            try:
                user_data = {
                    'id': request.user.id,
                    'username': request.user.username,
                    'email': request.user.email,
                    'google_id': social_account.uid,
                    'first_name': request.user.first_name,
                    'last_name': request.user.last_name,
                }
            except AttributeError as e:
                logger.error(f"Error accessing user attributes: {str(e)}")
                return Response({
                    "error": "User data error",
                    "code": "user_data_error",
                    "message": "Error accessing user information"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Success response with all necessary data
            logger.info(f"Successful Google login for user {request.user.email}")
            return Response({
                'message': 'Google login successful',
                'is_new_user': is_new_account,
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                },
                'user': user_data
            }, status=status.HTTP_200_OK)

        except SocialAccount.MultipleObjectsReturned:
            # Error 6: Multiple social accounts
            # Handles rare case where multiple social accounts exist for one user
            logger.error(f"Multiple Google accounts found for user {request.user.email}")
            return Response({
                "error": "Multiple accounts found",
                "code": "multiple_accounts",
                "message": "Multiple Google accounts linked to this user"
            }, status=status.HTTP_400_BAD_REQUEST)

        except ValidationError as e:
            # Error 7: Validation errors
            # Handles any validation errors during the process
            logger.error(f"Validation error during Google login: {str(e)}")
            return Response({
                "error": "Validation error",
                "code": "validation_error",
                "message": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Error 8: Unexpected errors
            # Catches any other unexpected errors
            logger.error(f"Unexpected error in Google login: {str(e)}")
            return Response({
                "error": "Login failed",
                "code": "unexpected_error",
                "message": "An unexpected error occurred during login"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GoogleLoginView(APIView):
    """
    Simplified Google login for testing
    Accepts Google token ID and returns JWT
    """
    def post(self, request):
        google_token = request.data.get('google_token')
        
        if not google_token:
            return Response(
                {'error': 'Google token is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # For testing, we'll accept any token and create/return a user
            email = request.data.get('email', 'test@gmail.com')
            name = request.data.get('name', 'Test User')
            
            # Try to get existing user
            user = User.objects.filter(email=email).first()
            
            if not user:
                # Create new user
                username = email.split('@')[0]
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=name
                )
                
                # Create social account
                SocialAccount.objects.create(
                    user=user,
                    provider='google',
                    uid=google_token,
                    extra_data={
                        'email': email,
                        'name': name
                    }
                )
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Google login successful',
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                },
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ProfileView(APIView):
    """
    Profile management endpoint
    - Get profile details
    - Update profile
    - Handles role information
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, username):
        try:
            profile = Profile.objects.get(user__username=username)
            serializer = ProfileSerializer(profile, context={'request': request})
            return Response(serializer.data)
        except Profile.DoesNotExist:
            raise NotFound('Profile not found')

    def put(self, request):
        # Get the current user's profile
        profile = request.user.profile
        
        # Make a copy of request data to modify safely
        data = request.data.copy()
        
        # Remove role from the data if the user is not an admin
        if 'role' in data and not (request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin')):
            data.pop('role')
            
        serializer = ProfileSerializer(profile, data=data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        # Only allow users to delete their own profile
        profile = request.user.profile
        
        # Delete the profile picture if it exists
        if profile.profile_picture:
            profile.profile_picture.delete()
            
        # Note: This doesn't delete the user, just clears profile data
        profile.bio = ''
        profile.location = ''
        profile.website = ''
        profile.birth_date = None
        profile.save()
        
        return Response({
            'message': 'Profile information cleared successfully'
        }, status=status.HTTP_200_OK)

class ProfilePictureUploadView(APIView):
    """
    Profile picture upload endpoint
    - Upload new profile picture
    - Delete existing profile picture
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        profile = request.user.profile
        
        if 'profile_picture' not in request.FILES:
            return Response(
                {'error': 'No image file provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        profile.profile_picture = request.FILES['profile_picture']
        profile.save()
        
        return Response({
            'message': 'Profile picture updated successfully',
            'profile_picture_url': profile.profile_picture.url
        })
        
    def delete(self, request):
        profile = request.user.profile
        if profile.profile_picture:
            profile.profile_picture.delete()
        return Response({'message': 'Profile picture removed'})

class FollowUserView(APIView):
    """
    User follow/unfollow endpoint
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, username):
        try:
            user_to_follow = User.objects.get(username=username)
            profile_to_follow = user_to_follow.profile
            
            if request.user == user_to_follow:
                return Response(
                    {'error': 'You cannot follow yourself'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if this is an unfollow request by examining the URL path
            is_unfollow_request = 'unfollow' in request.path
            
            if is_unfollow_request:
                # Handle unfollow request
                if request.user in profile_to_follow.followers.all():
                    profile_to_follow.followers.remove(request.user)
                    
                    # Update counts
                    profile_to_follow.update_counts()
                    request.user.profile.update_counts()
                    
                    return Response({
                        'message': f'Successfully unfollowed {username}',
                        'followers_count': profile_to_follow.followers_count
                    })
                else:
                    return Response(
                        {'error': 'You are not following this user'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                # Handle follow request
                if request.user in profile_to_follow.followers.all():
                    return Response(
                        {'error': 'You are already following this user'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    profile_to_follow.followers.add(request.user)
                    
                    # Update counts
                    profile_to_follow.update_counts()
                    request.user.profile.update_counts()
                    
                    return Response({
                        'message': f'Successfully followed {username}',
                        'followers_count': profile_to_follow.followers_count
                    })
                
        except User.DoesNotExist:
            raise NotFound('User not found')


class NewsFeedView(APIView):
    """
    News Feed endpoint with privacy filtering
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Existing code...
        
        # Get pagination parameters
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 20))
        
        # Get filter parameters
        feed_type = request.query_params.get('type', 'all')  # all, following, liked
        time_range = request.query_params.get('time', '7d')  # 24h, 7d, 30d, all
        
        # Calculate time filter
        time_filter = self._get_time_filter(time_range)
        
        # Get filtered posts with privacy settings applied
        posts = self._get_filtered_posts(
            request.user, 
            feed_type, 
            time_filter
        )
        
        # Apply pagination
        paginator = self._paginate_queryset(posts, page, page_size)
        
        if not paginator:
            return Response({
                'error': 'Invalid page number'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Serialize results
        serializer = PostSerializer(
            paginator['posts'],
            many=True,
            context={'request': request}
        )
        
        return Response({
            'results': serializer.data,
            'page': page,
            'total_pages': paginator['total_pages'],
            'has_next': paginator['has_next'],
            'has_previous': paginator['has_previous']
        })
    
    def _get_time_filter(self, time_range):
        """Calculate time filter based on range parameter"""
        now = timezone.now()
        
        if time_range == '24h':
            return now - timedelta(days=1)
        elif time_range == '7d':
            return now - timedelta(days=7)
        elif time_range == '30d':
            return now - timedelta(days=30)
        return None
    
    def _get_filtered_posts(self, user, feed_type, time_filter):
        """Get posts with privacy filtering applied"""
        base_query = Post.objects.select_related(
            'author',
            'author__profile'
        ).prefetch_related(
            'comments',
            'likes'
        )
        
        # Apply time filter if specified
        if time_filter:
            base_query = base_query.filter(created_at__gte=time_filter)
            
        # Apply feed type filter
        if feed_type == 'following':
            following_users = []
            if hasattr(user, 'following'):
                following_users = user.following.all()
            base_query = base_query.filter(author__in=following_users)
        elif feed_type == 'liked':
            base_query = base_query.filter(likes__user=user)
            
        # Apply privacy filtering if not admin/moderator
        if not (user.is_staff or (hasattr(user, 'profile') and user.profile.role in ['admin', 'moderator'])):
            # User's own posts
            privacy_filter = Q(author=user)
            
            # Public posts
            privacy_filter |= Q(privacy='public')
            
            # Followers-only posts from users the current user follows
            following_ids = []
            if hasattr(user, 'following'):
                following_ids = user.following.values_list('id', flat=True)
            
            privacy_filter |= Q(privacy='followers', author_id__in=following_ids)
            
            # Apply the filter
            base_query = base_query.filter(privacy_filter)
        
        # Annotate with engagement metrics for sorting
        return base_query.annotate(
            db_engagement_score=Count('likes') + Count('comments') * 2
        ).order_by('-created_at', '-db_engagement_score')
    
    def _paginate_queryset(self, queryset, page, page_size):
        """Apply pagination to queryset"""
        start = (page - 1) * page_size
        end = start + page_size
        
        total_posts = queryset.count()
        total_pages = (total_posts + page_size - 1) // page_size
        
        if page > total_pages and total_posts > 0:
            return None
            
        return {
            'posts': queryset[start:end],
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_previous': page > 1
        }


class TrendingPostsView(APIView):
    """
    Endpoint to retrieve trending posts based on engagement
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get trending posts from cache
        cache_key = "trending_posts"
        trending_posts = cache.get(cache_key)
        
        if not trending_posts:
            # Calculate trending posts for the last 24 hours
            last_24h = timezone.now() - timedelta(days=1)
            
            posts = Post.objects.filter(
                created_at__gte=last_24h
            ).annotate(
                engagement=Count('likes') + Count('comments') * 2
            ).order_by('-engagement')[:10]
            
            serializer = PostSerializer(posts, many=True, context={'request': request})
            trending_posts = serializer.data
            
            # Cache for 1 hour
            cache.set(cache_key, trending_posts, 3600)
        
        return Response(trending_posts)
    
    
class UserRoleManagementView(APIView):
    """
    User role management endpoint (admin only)
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request, user_id):
        # Check if the requesting user is an admin
        if not (request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.role == 'admin')):
            raise PermissionDenied('Admin access required')
            
        try:
            user = User.objects.get(id=user_id)
            role = request.data.get('role')
            
            # Validate the role
            valid_roles = ['admin', 'moderator', 'user']
            if role not in valid_roles:
                return Response(
                    {'error': f"Invalid role. Must be one of: {', '.join(valid_roles)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Update the user's role
            if not hasattr(user, 'profile'):
                # Create profile if it doesn't exist
                Profile.objects.create(user=user, role=role)
            else:
                # Update existing profile
                profile = user.profile
                profile.role = role
                profile.save()
            
            return Response({
                'message': f"User {user.username} role updated to {role}",
                'user_id': user.id,
                'username': user.username,
                'role': role
            })
            
        except User.DoesNotExist:
            raise NotFound('User not found')