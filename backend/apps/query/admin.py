from django.contrib import admin
from .models import SavedQuery, QueryHistory

@admin.register(SavedQuery)
class SavedQueryAdmin(admin.ModelAdmin):
    list_display = ['name', 'author', 'category', 'is_public', 'is_favorite', 'run_count', 'updated_at']
    list_filter = ['category', 'is_public', 'is_favorite']
    search_fields = ['name', 'description', 'query']
    readonly_fields = ['id', 'created_at', 'updated_at', 'last_run_at', 'run_count']

@admin.register(QueryHistory)
class QueryHistoryAdmin(admin.ModelAdmin):
    list_display = ['executed_at', 'query', 'execution_time_ms', 'result_count', 'was_successful']
    list_filter = ['was_successful']
    date_hierarchy = 'executed_at'



