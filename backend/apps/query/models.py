"""
Dark Knight Phantom SIEM - Query Models
Saved queries and query history
"""
from django.db import models
from django.utils import timezone
import uuid


class SavedQuery(models.Model):
    """Saved PQL queries for reuse"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    query = models.TextField()
    
    # Metadata
    author = models.CharField(max_length=255, blank=True)
    is_public = models.BooleanField(default=True)
    is_favorite = models.BooleanField(default=False)
    
    # Categorization
    category = models.CharField(max_length=100, blank=True)
    tags = models.JSONField(default=list)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    run_count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'saved_queries'
        ordering = ['-updated_at']
    
    def __str__(self):
        return self.name


class QueryHistory(models.Model):
    """Query execution history"""
    query = models.TextField()
    executed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    execution_time_ms = models.IntegerField(default=0)
    result_count = models.IntegerField(default=0)
    was_successful = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # User info
    executed_by = models.CharField(max_length=255, blank=True)
    
    class Meta:
        db_table = 'query_history'
        ordering = ['-executed_at']
    
    def __str__(self):
        return f"Query at {self.executed_at}"



