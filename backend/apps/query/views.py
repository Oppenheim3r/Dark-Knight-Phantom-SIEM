"""
Dark Knight Phantom SIEM - Query Views
PQL Query execution endpoints
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
import time
import logging

from .models import SavedQuery, QueryHistory
from .serializers import SavedQuerySerializer, QueryHistorySerializer, PQLQuerySerializer
from .pql_engine import execute_pql, PQLSyntaxError, PQLExecutionError

logger = logging.getLogger(__name__)


class PQLExecuteView(APIView):
    """Execute PQL queries"""
    
    def post(self, request):
        # Handle both JSON and form data
        if hasattr(request, 'data') and request.data:
            serializer = PQLQuerySerializer(data=request.data)
        else:
            # Fallback to raw JSON
            import json
            try:
                data = json.loads(request.body) if hasattr(request, 'body') else {}
                serializer = PQLQuerySerializer(data=data)
            except:
                return Response(
                    {'error': 'Invalid request format', 'message': 'Expected JSON with "query" field'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if not serializer.is_valid():
            logger.error(f"PQL serializer errors: {serializer.errors}")
            return Response(
                {'status': 'error', 'error_type': 'validation_error', 'message': 'Invalid request', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        query_string = serializer.validated_data.get('query', '')
        if not query_string:
            return Response(
                {'status': 'error', 'error_type': 'validation_error', 'message': 'Query string is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        save_history = serializer.validated_data.get('save_history', True)
        
        logger.info(f"Executing PQL query: {query_string[:100]}")
        start_time = time.time()
        
        try:
            limit = serializer.validated_data.get('limit', 100)
            results = execute_pql(query_string, limit=limit)
            execution_time = int((time.time() - start_time) * 1000)
            logger.info(f"PQL query executed successfully in {execution_time}ms, returned {len(results) if isinstance(results, list) else 1} results")
            
            # Save to history
            if save_history:
                QueryHistory.objects.create(
                    query=query_string,
                    execution_time_ms=execution_time,
                    result_count=len(results) if isinstance(results, list) else 1,
                    was_successful=True,
                )
            
            return Response({
                'status': 'success',
                'query': query_string,
                'execution_time_ms': execution_time,
                'result_count': len(results) if isinstance(results, list) else 1,
                'results': results,
            })
            
        except PQLSyntaxError as e:
            if save_history:
                QueryHistory.objects.create(
                    query=query_string,
                    execution_time_ms=int((time.time() - start_time) * 1000),
                    was_successful=False,
                    error_message=str(e),
                )
            
            return Response({
                'status': 'error',
                'error_type': 'syntax_error',
                'message': str(e),
                'query': query_string,
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except PQLExecutionError as e:
            if save_history:
                QueryHistory.objects.create(
                    query=query_string,
                    execution_time_ms=int((time.time() - start_time) * 1000),
                    was_successful=False,
                    error_message=str(e),
                )
            
            return Response({
                'status': 'error',
                'error_type': 'execution_error',
                'message': str(e),
                'query': query_string,
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except Exception as e:
            logger.exception(f"PQL execution error: {str(e)}")
            execution_time = int((time.time() - start_time) * 1000)
            if save_history:
                QueryHistory.objects.create(
                    query=query_string,
                    execution_time_ms=execution_time,
                    was_successful=False,
                    error_message=str(e),
                )
            return Response({
                'status': 'error',
                'error_type': 'internal_error',
                'message': str(e),
                'query': query_string,
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SavedQueryViewSet(viewsets.ModelViewSet):
    """API endpoints for saved queries"""
    queryset = SavedQuery.objects.all()
    serializer_class = SavedQuerySerializer
    search_fields = ['name', 'description', 'query']
    ordering = ['-updated_at']
    
    @action(detail=True, methods=['post'])
    def run(self, request, pk=None):
        """Run a saved query"""
        saved_query = self.get_object()
        
        start_time = time.time()
        
        try:
            results = execute_pql(saved_query.query)
            execution_time = int((time.time() - start_time) * 1000)
            
            # Update run count
            saved_query.run_count += 1
            saved_query.last_run_at = timezone.now()
            saved_query.save()
            
            # Save to history
            QueryHistory.objects.create(
                query=saved_query.query,
                execution_time_ms=execution_time,
                result_count=len(results) if isinstance(results, list) else 1,
                was_successful=True,
            )
            
            return Response({
                'status': 'success',
                'query_name': saved_query.name,
                'query': saved_query.query,
                'execution_time_ms': execution_time,
                'result_count': len(results) if isinstance(results, list) else 1,
                'results': results,
            })
            
        except (PQLSyntaxError, PQLExecutionError) as e:
            return Response({
                'status': 'error',
                'message': str(e),
            }, status=status.HTTP_400_BAD_REQUEST)


class QueryHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoints for query history"""
    queryset = QueryHistory.objects.all()
    serializer_class = QueryHistorySerializer
    ordering = ['-executed_at']

