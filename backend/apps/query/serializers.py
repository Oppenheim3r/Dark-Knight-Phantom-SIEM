"""
Dark Knight Phantom SIEM - Query Serializers
"""
from rest_framework import serializers
from .models import SavedQuery, QueryHistory


class SavedQuerySerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedQuery
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_run_at', 'run_count']


class QueryHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = QueryHistory
        fields = '__all__'
        read_only_fields = ['executed_at']


class PQLQuerySerializer(serializers.Serializer):
    """Serializer for PQL query execution"""
    query = serializers.CharField()
    limit = serializers.IntegerField(required=False, default=100, max_value=5000)
    save_history = serializers.BooleanField(required=False, default=True)



