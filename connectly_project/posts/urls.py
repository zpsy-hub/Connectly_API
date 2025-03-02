from django.urls import path
from .import views
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    UserCreate,
    UserListView,
    PostListCreate,
    CommentListCreate,
    UserLoginView,
    PostDetailView,
    ProtectedView,
    UserDetailView,
    CommentDetailView,
    LikeView, 
    PostLikesView,
    UserLogoutView,
    CustomTokenObtainPairView,
    GoogleLoginView,
    PostCommentsView,
    ProfileView,
    ProfilePictureUploadView,
    FollowUserView,
    NewsFeedView,
    TrendingPostsView,
)


urlpatterns = [
    
    # JWT endpoints
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/', UserLoginView.as_view(), name='user_login'),
    path('logout/', UserLogoutView.as_view(), name='user_logout'),
    path('google-login-success/', views.GoogleLoginSuccessView.as_view(), name='google-login-success'),
    
    # User Authentication and Registration
    path('users/', UserCreate.as_view(), name='user-create'),  # User Registration (Create User)
    path('users/list/', UserListView.as_view(), name='user-list'),  # List all users (Admin only)
    path('users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),  # Retrieve user details
    path('users/delete/<int:pk>/', UserDetailView.as_view(), name='delete-user'),  # Delete user (Admin only)
    path('auth/google/login/', GoogleLoginView.as_view(), name='google-login'),

    # Post Management
    path('posts/', PostListCreate.as_view(), name='post-list-create'),  # List and create posts
    path('posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),  # Retrieve, update, or delete post

    # Comment Management
    path('comments/', CommentListCreate.as_view(), name='comment-list-create'),  # List and create comments
    path('comments/<int:pk>/', CommentDetailView.as_view(), name='comment-detail'),  # Retrieve, update, or delete comment
    path('posts/<int:post_id>/comments/', PostCommentsView.as_view(), name='post-comments'),

    # Protected endpoint for testing authentication
    path('protected/', ProtectedView.as_view(), name='protected-view'),
    
     # Add the SingletonTestView
    #path('test-singleton/', SingletonTestView.as_view(), name='test-singleton'),
    
    # Add the LikeView and PostLikesView
    path('posts/<int:post_id>/like/', LikeView.as_view(), name='post-like'),
    path('posts/<int:post_id>/likes/', PostLikesView.as_view(), name='post-likes-list'),
    
    # Add the ProfileView, ProfilePictureUploadView, and FollowUserView
    path('profile/<str:username>/', ProfileView.as_view(), name='profile-detail'),
    path('profile/update/', ProfileView.as_view(), name='profile-update'),
    path('profile/picture/', ProfilePictureUploadView.as_view(), name='profile-picture'),
    path('profile/<str:username>/follow/', FollowUserView.as_view(), name='follow-user'),
    
    # Feed endpoints
    path('feed/', NewsFeedView.as_view(), name='news-feed'),
    path('feed/trending/', TrendingPostsView.as_view(), name='trending-posts'),
]
