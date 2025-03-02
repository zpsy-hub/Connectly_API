from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from cloudinary.models import CloudinaryField
from django.utils import timezone
from datetime import timedelta


# class User(models.Model):
#     username = models.CharField(max_length=100, unique=True)  # User's unique username
#     email = models.EmailField(unique=True)  # User's unique email
#     password = models.CharField(max_length=255)  # Field to store the hashed password
#     created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the user was created

#     def set_password(self, raw_password):
#         """Hash and set the password."""
#         self.password = make_password(raw_password)

#     def check_password(self, raw_password):
#         """Check if the provided password matches the stored hash."""
#         from django.contrib.auth.hashers import check_password
#         return check_password(raw_password, self.password)

#     def __str__(self):
#         return self.username



class Post(models.Model):
    POST_TYPES = (
        ('image', 'Image'),
        ('video', 'Video'),
        ('text', 'Text'),
    )
    
    # Fields
    title = models.CharField(max_length=255)  # Add title field to store the title of the post
    content = models.TextField()  # Post content
    post_type = models.CharField(max_length=50, choices=POST_TYPES)  # Post type (image, video, etc.)
    metadata = models.JSONField(null=True, blank=True)  # Store metadata in a JSON format (file_size, duration, etc.)
    created_at = models.DateTimeField(auto_now_add=True)  # Auto-filled with timestamp
    author = models.ForeignKey(User, on_delete=models.CASCADE)  # Author of the post (foreign key to User)

    def __str__(self):
        return self.title
    
    def get_author_profile_picture(self):
        """Get the author's profile picture URL"""
        return self.author.profile.profile_picture.url if self.author.profile.profile_picture else None
    
    class Meta:
        indexes = [
            models.Index(fields=['-created_at']),  # Index for date-based sorting
            models.Index(fields=['author']),       # Index for author filtering
        ]
    
    @property
    def engagement_score(self):
        """Calculate post engagement score"""
        return (self.likes.count() + self.comments.count() * 2)
    
    @classmethod
    def get_feed_for_user(cls, user, feed_type='all', time_filter=None):
        """
        Get personalized feed for user
        - Supports different feed types (all, following, liked)
        - Optional time filtering
        """
        base_query = cls.objects.select_related(
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
            following_users = user.profile.following.all()
            base_query = base_query.filter(author__in=following_users)
        elif feed_type == 'liked':
            base_query = base_query.filter(likes__user=user)
        
        # Annotate with engagement metrics
        return base_query.annotate(
            engagement_score=models.Count('likes') + models.Count('comments') * 2
        ).order_by('-created_at', '-engagement_score')
    
    @classmethod
    def get_trending_posts(cls, hours=24):
        """Get trending posts based on engagement in the last n hours"""
        time_threshold = timezone.now() - timedelta(hours=hours)
        
        return cls.objects.filter(
            created_at__gte=time_threshold
        ).annotate(
            engagement=models.Count('likes') + models.Count('comments') * 2
        ).order_by('-engagement')

class Comment(models.Model):
    text = models.TextField()  # The text content of the comment
    author = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)  # The user who commented
    post = models.ForeignKey(Post, related_name='comments', on_delete=models.CASCADE)  # The post the comment belongs to
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the comment was created

    def __str__(self):
        return f"Comment by {self.author.username} on Post {self.post.id}"

    def get_author_profile_picture(self):
        """Get the commenter's profile picture URL"""
        return self.author.profile.profile_picture.url if self.author.profile.profile_picture else None


class Like(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='likes')
    post = models.ForeignKey('Post', on_delete=models.CASCADE, related_name='likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Ensure a user can only like a post once
        unique_together = ('user', 'post')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} likes {self.post.title}"

    def clean(self):
        # Additional validation if needed
        if self.user == self.post.author:
            raise ValidationError("Users cannot like their own posts")

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_picture = CloudinaryField('image', null=True, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=100, blank=True)
    website = models.URLField(max_length=200, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    followers = models.ManyToManyField(User, related_name='following', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Social media statistics
    posts_count = models.PositiveIntegerField(default=0)
    followers_count = models.PositiveIntegerField(default=0)
    following_count = models.PositiveIntegerField(default=0)
    
    def __str__(self):
        return f"{self.user.username}'s profile"
    
    def update_counts(self):
        """Update profile statistics"""
        self.posts_count = self.user.post_set.count()
        self.followers_count = self.followers.count()
        self.following_count = self.user.following.count()
        self.save()

    def get_feed_preferences(self):
        """Get user's feed preferences"""
        return {
            'preferred_feed_type': 'following',  # Default to following feed
            'preferred_time_range': '7d',        # Default to 7 days
            'preferred_page_size': 20            # Default page size
        }
    
    def get_feed(self, feed_type=None, time_range=None):
        """Get personalized feed based on user preferences"""
        preferences = self.get_feed_preferences()
        
        feed_type = feed_type or preferences['preferred_feed_type']
        time_range = time_range or preferences['preferred_time_range']
        
        time_filter = None
        if time_range == '24h':
            time_filter = timezone.now() - timedelta(days=1)
        elif time_range == '7d':
            time_filter = timezone.now() - timedelta(days=7)
        elif time_range == '30d':
            time_filter = timezone.now() - timedelta(days=30)
            
        return Post.get_feed_for_user(
            user=self.user,
            feed_type=feed_type,
            time_filter=time_filter
        )