# posts/management/commands/initialize_roles.py
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from posts.models import Profile

class Command(BaseCommand):
    help = "Initialize default roles for users"

    def handle(self, *args, **options):
        # Set staff users as admins
        staff_users = User.objects.filter(is_staff=True)
        for user in staff_users:
            profile, created = Profile.objects.get_or_create(user=user)
            profile.role = 'admin'
            profile.save()
            self.stdout.write(self.style.SUCCESS(f"Set {user.username} as admin"))
            
        # Set regular users as 'user' role if not already set
        regular_users = User.objects.filter(is_staff=False)
        for user in regular_users:
            profile, created = Profile.objects.get_or_create(user=user)
            if created or not profile.role:
                profile.role = 'user'
                profile.save()
                self.stdout.write(self.style.SUCCESS(f"Set {user.username} as regular user"))
                
        self.stdout.write(self.style.SUCCESS("Role initialization complete"))