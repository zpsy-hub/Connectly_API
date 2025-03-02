from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Post, Comment, Like, Profile

class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    followers_count = serializers.IntegerField(read_only=True)
    following_count = serializers.IntegerField(read_only=True)
    posts_count = serializers.IntegerField(read_only=True)
    is_following = serializers.SerializerMethodField()
    
    class Meta:
        model = Profile
        fields = [
            'id', 'username', 'email', 'profile_picture', 'bio',
            'location', 'website', 'birth_date', 'followers_count',
            'following_count', 'posts_count', 'is_following',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_is_following(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.followers.filter(id=request.user.id).exists()
        return False

    def validate_profile_picture(self, value):
        """Validate profile picture size and format"""
        if value:
            if value.size > 5 * 1024 * 1024:  # 5MB limit
                raise serializers.ValidationError("Profile picture size cannot exceed 5MB")
            
            allowed_formats = ['image/jpeg', 'image/png', 'image/gif']
            if value.content_type not in allowed_formats:
                raise serializers.ValidationError("Only JPEG, PNG and GIF images are allowed")
        return value
    
class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    """
    Secure User Serializer
    - Excludes sensitive information like password from the response
    - Validates unique username/email
    """
    password = serializers.CharField(
        write_only=True,  # Never returned in responses
        required=True,
        min_length=8,  # Minimum password length
        error_messages={
            'min_length': 'Password must be at least 8 characters long.'
        }
    )

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'profile', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_username(self, value):
        """
        Additional username validation
        - Prevent duplicate usernames
        - Enforce naming rules
        """
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        
        # Optional: Add more username validation rules
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        
        return value

    def validate_email(self, value):
        """
        Email validation
        - Prevent duplicate emails
        - Basic email format check
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        
        return value

    def create(self, validated_data):
        """
        Secure user creation
        - Use create_user for proper password hashing
        """
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

    def update(self, instance, validated_data):
        """
        Secure user update
        - Handle password hashing and ensure other fields are updated
        """
        password = validated_data.get('password', None)
        if password:
            instance.set_password(password)  # Hash the new password
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.save()
        return instance



class PostSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    author_profile = ProfileSerializer(source='author.profile', read_only=True)
    """
    Complete Post Serializer
    - Handles post creation, updating, and retrieval
    - Includes likes functionality
    - Validates post content and metadata
    - Prevents unauthorized author assignment
    """
    
    # Basic fields
    author = serializers.SlugRelatedField(
        slug_field='username',
        read_only=True
    )
    
    # Likes-related fields
    likes_count = serializers.SerializerMethodField()
    is_liked_by_user = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Post
        fields = [
            'id',
            'title',
            'content',
            'post_type',
            'metadata',
            'author',
            'author_profile',
            'created_at',
            'likes_count',
            'is_liked_by_user',
            'comments_count'
        ]
        read_only_fields = [
            'author',
            'created_at',
            'likes_count',
            'is_liked_by_user',
            'comments_count'
        ]

    def get_likes_count(self, obj):
        """Get the total number of likes for the post"""
        return obj.likes.count()

    def get_is_liked_by_user(self, obj):
        """Check if the current user has liked the post"""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user).exists()
        return False

    def get_comments_count(self, obj):
        """Get the total number of comments on the post"""
        return obj.comments.count()

    def validate_title(self, value):
        """Validate post title"""
        if not value or value.strip() == "":
            raise serializers.ValidationError("Post title cannot be empty.")
        
        if len(value) > 255:
            raise serializers.ValidationError("Post title is too long. Maximum 255 characters allowed.")
        
        return value.strip()

    def validate_content(self, value):
        """Validate post content"""
        if not value or value.strip() == "":
            raise serializers.ValidationError("Post content cannot be empty.")
        
        if len(value) > 5000:  # Adjust max length as needed
            raise serializers.ValidationError("Post content is too long. Maximum 5000 characters allowed.")
        
        return value.strip()

    def validate_post_type(self, value):
        """Validate post type"""
        valid_types = dict(Post.POST_TYPES).keys()
        if value not in valid_types:
            raise serializers.ValidationError(
                f"Invalid post type. Must be one of: {', '.join(valid_types)}"
            )
        return value

    def validate_metadata(self, value):
        """Validate metadata based on post type"""
        if not value:
            return {}
            
        post_type = self.initial_data.get('post_type')
        
        if post_type == 'image':
            required_fields = ['width', 'height', 'format']
            for field in required_fields:
                if field not in value:
                    raise serializers.ValidationError(
                        f"Image posts require '{field}' in metadata"
                    )
                    
        elif post_type == 'video':
            required_fields = ['duration', 'format']
            for field in required_fields:
                if field not in value:
                    raise serializers.ValidationError(
                        f"Video posts require '{field}' in metadata"
                    )
                    
        return value

    def validate(self, data):
        """Additional cross-field validation"""
        # Ensure post type and content match
        post_type = data.get('post_type')
        content = data.get('content')
        
        if post_type in ['image', 'video']:
            # For media posts, content should contain a valid URL or file path
            if not content or not (
                content.startswith('http') or 
                content.startswith('/')
            ):
                raise serializers.ValidationError(
                    f"{post_type.capitalize()} posts require a valid media URL or path"
                )
        
        return data

    def create(self, validated_data):
        """Create new post with authenticated user as author"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(
                "Must be authenticated to create a post"
            )
            
        validated_data['author'] = request.user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        """Update post while preserving the author"""
        # Prevent changing the author
        validated_data.pop('author', None)
        
        # Update the instance
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        instance.save()
        return instance

    def to_representation(self, instance):
        """Customize the output representation"""
        representation = super().to_representation(instance)
        
        # Add formatted timestamp
        representation['created_at'] = instance.created_at.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        
        # Add recent likes (last 3 users who liked)
        recent_likes = instance.likes.order_by('-created_at')[:3]
        representation['recent_likes'] = [
            {
                'user': like.user.username,
                'timestamp': like.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for like in recent_likes
        ]
        
        return representation


class CommentSerializer(serializers.ModelSerializer):
    author_profile = ProfileSerializer(source='author.profile', read_only=True)
    """
    Secure Comment Serializer
    - Validates comment creation
    - Prevents unauthorized author/post assignments
    """

    class Meta:
        model = Comment
        fields = ['id', 'text', 'author', 'author_profile', 'post', 'created_at']
        read_only_fields = ['author', 'created_at']

    def validate_text(self, value):
        """
        Comment text validation
        - Prevent empty comments
        - Optional: Add text length restrictions
        """
        if not value or value.strip() == "":
            raise serializers.ValidationError("Comment text cannot be empty.")
        
        if len(value) > 500:  # Example max length
            raise serializers.ValidationError("Comment text is too long.")
        
        return value

    def validate(self, data):
        """
        Additional validation for comment creation
        - Verify post exists
        """
        post = data.get('post')
        if not post:
            raise serializers.ValidationError("Post is required.")
        
        # Check if the post exists in the database
        try:
            post_instance = Post.objects.get(pk=post.id)
        except Post.DoesNotExist:
            raise serializers.ValidationError("The post does not exist.")
        
        return data

    def create(self, validated_data):
        """
        Secure comment creation
        - Enforce author as current authenticated user
        """
        # Ensure author is set from request context
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)


class LikeSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(
        slug_field='username',
        read_only=True
    )
    
    class Meta:
        model = Like
        fields = ['id', 'user', 'post', 'created_at']
        read_only_fields = ['user', 'created_at']

