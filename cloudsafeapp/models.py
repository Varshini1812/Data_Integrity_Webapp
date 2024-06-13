from django.db import models
from django.contrib.auth.models import User

class VerificationResult(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=10)
    timestamp = models.DateTimeField()

    def __str__(self):
        return f"{self.user.username} - {self.status} at {self.timestamp}"

from django.db import models
from django.conf import settings  # Add this import

class TaskHistory(models.Model):
    task_name = models.CharField(max_length=255)  # Add this field
    action = models.CharField(max_length=255)  # Assuming this was the previous task_name field
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.task_name} - {self.timestamp}"



