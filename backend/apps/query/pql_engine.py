"""
Dark Knight Phantom SIEM - Phantom Query Language (PQL) Engine
A custom query language for security event analysis
"""
import re
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q, Count, Sum, Avg, Min, Max
from apps.events.models import SecurityEvent


class PQLSyntaxError(Exception):
    """PQL Syntax Error"""
    pass


class PQLExecutionError(Exception):
    """PQL Execution Error"""
    pass


class PQLToken:
    """Token types for PQL lexer"""
    KEYWORD = 'KEYWORD'
    IDENTIFIER = 'IDENTIFIER'
    STRING = 'STRING'
    NUMBER = 'NUMBER'
    OPERATOR = 'OPERATOR'
    COMPARISON = 'COMPARISON'
    LOGICAL = 'LOGICAL'
    PIPE = 'PIPE'
    COMMA = 'COMMA'
    LPAREN = 'LPAREN'
    RPAREN = 'RPAREN'
    EOF = 'EOF'


class PQLLexer:
    """Tokenizer for PQL"""
    
    KEYWORDS = {
        'SEARCH', 'HUNT', 'AGGREGATE', 'TIMELINE', 'CORRELATE',
        'WHERE', 'AND', 'OR', 'NOT', 'IN', 'CONTAINS', 'LIKE',
        'ORDER', 'BY', 'ASC', 'DESC', 'LIMIT', 'OFFSET',
        'GROUP', 'HAVING', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
        'DISTINCT', 'TOP', 'WITHIN', 'FROM', 'TO', 'AS',
        'NOW', 'TRUE', 'FALSE', 'NULL'
    }
    
    def __init__(self, query):
        self.query = query
        self.pos = 0
        self.tokens = []
    
    def tokenize(self):
        """Tokenize the PQL query"""
        while self.pos < len(self.query):
            self._skip_whitespace()
            if self.pos >= len(self.query):
                break
            
            char = self.query[self.pos]
            
            # String literals
            if char in '"\'':
                self.tokens.append(self._read_string())
            # Numbers
            elif char.isdigit() or (char == '-' and self.pos + 1 < len(self.query) and self.query[self.pos + 1].isdigit()):
                self.tokens.append(self._read_number())
            # Identifiers and keywords
            elif char.isalpha() or char == '_':
                self.tokens.append(self._read_identifier())
            # Operators
            elif char in '=!<>':
                self.tokens.append(self._read_comparison())
            elif char == '|':
                self.tokens.append((PQLToken.PIPE, '|'))
                self.pos += 1
            elif char == ',':
                self.tokens.append((PQLToken.COMMA, ','))
                self.pos += 1
            elif char == '(':
                self.tokens.append((PQLToken.LPAREN, '('))
                self.pos += 1
            elif char == ')':
                self.tokens.append((PQLToken.RPAREN, ')'))
                self.pos += 1
            else:
                self.pos += 1  # Skip unknown characters
        
        self.tokens.append((PQLToken.EOF, None))
        return self.tokens
    
    def _skip_whitespace(self):
        while self.pos < len(self.query) and self.query[self.pos].isspace():
            self.pos += 1
    
    def _read_string(self):
        quote_char = self.query[self.pos]
        self.pos += 1
        start = self.pos
        
        while self.pos < len(self.query) and self.query[self.pos] != quote_char:
            if self.query[self.pos] == '\\':
                self.pos += 2
            else:
                self.pos += 1
        
        value = self.query[start:self.pos]
        self.pos += 1  # Skip closing quote
        return (PQLToken.STRING, value)
    
    def _read_number(self):
        start = self.pos
        if self.query[self.pos] == '-':
            self.pos += 1
        
        while self.pos < len(self.query) and (self.query[self.pos].isdigit() or self.query[self.pos] == '.'):
            self.pos += 1
        
        # Check for time units (h, m, s, d, w)
        if self.pos < len(self.query) and self.query[self.pos] in 'hmsdw':
            self.pos += 1
        
        return (PQLToken.NUMBER, self.query[start:self.pos])
    
    def _read_identifier(self):
        start = self.pos
        while self.pos < len(self.query) and (self.query[self.pos].isalnum() or self.query[self.pos] == '_'):
            self.pos += 1
        
        value = self.query[start:self.pos]
        upper_value = value.upper()
        
        if upper_value in self.KEYWORDS:
            if upper_value in ('AND', 'OR', 'NOT'):
                return (PQLToken.LOGICAL, upper_value)
            return (PQLToken.KEYWORD, upper_value)
        
        return (PQLToken.IDENTIFIER, value)
    
    def _read_comparison(self):
        start = self.pos
        while self.pos < len(self.query) and self.query[self.pos] in '=!<>':
            self.pos += 1
        return (PQLToken.COMPARISON, self.query[start:self.pos])


class PQLParser:
    """Parser for PQL"""
    
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
    
    def current_token(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return (PQLToken.EOF, None)
    
    def consume(self, expected_type=None, expected_value=None):
        token = self.current_token()
        if expected_type and token[0] != expected_type:
            raise PQLSyntaxError(f"Expected {expected_type}, got {token[0]}")
        if expected_value and token[1] != expected_value:
            raise PQLSyntaxError(f"Expected '{expected_value}', got '{token[1]}'")
        self.pos += 1
        return token
    
    def parse(self):
        """Parse the tokens into an AST"""
        token = self.current_token()
        
        if token[0] == PQLToken.KEYWORD:
            if token[1] == 'SEARCH':
                return self.parse_search()
            elif token[1] == 'HUNT':
                return self.parse_hunt()
            elif token[1] == 'AGGREGATE':
                return self.parse_aggregate()
        
        raise PQLSyntaxError(f"Unexpected token: {token}")
    
    def parse_search(self):
        """Parse SEARCH command"""
        self.consume(PQLToken.KEYWORD, 'SEARCH')
        
        # Parse source (optional)
        source = 'events'
        if self.current_token()[0] == PQLToken.IDENTIFIER:
            source = self.consume(PQLToken.IDENTIFIER)[1]
        
        result = {
            'command': 'SEARCH',
            'source': source,
            'conditions': [],
            'order_by': None,
            'order_dir': 'DESC',
            'limit': 100,
            'offset': 0,
        }
        
        # Parse WHERE clause
        if self.current_token()[1] == 'WHERE':
            self.consume(PQLToken.KEYWORD, 'WHERE')
            result['conditions'] = self.parse_conditions()
        
        # Parse ORDER BY
        if self.current_token()[1] == 'ORDER':
            self.consume(PQLToken.KEYWORD, 'ORDER')
            self.consume(PQLToken.KEYWORD, 'BY')
            result['order_by'] = self.consume(PQLToken.IDENTIFIER)[1]
            
            if self.current_token()[1] in ('ASC', 'DESC'):
                result['order_dir'] = self.consume(PQLToken.KEYWORD)[1]
        
        # Parse LIMIT
        if self.current_token()[1] == 'LIMIT':
            self.consume(PQLToken.KEYWORD, 'LIMIT')
            result['limit'] = int(self.consume(PQLToken.NUMBER)[1])
        
        return result
    
    def parse_hunt(self):
        """Parse HUNT command (similar to SEARCH but for threat hunting)"""
        self.consume(PQLToken.KEYWORD, 'HUNT')
        
        target = 'events'
        if self.current_token()[0] == PQLToken.IDENTIFIER:
            target = self.consume(PQLToken.IDENTIFIER)[1]
        
        result = {
            'command': 'HUNT',
            'target': target,
            'conditions': [],
            'group_by': None,
            'limit': 500,
        }
        
        if self.current_token()[1] == 'WHERE':
            self.consume(PQLToken.KEYWORD, 'WHERE')
            result['conditions'] = self.parse_conditions()
        
        if self.current_token()[1] == 'GROUP':
            self.consume(PQLToken.KEYWORD, 'GROUP')
            self.consume(PQLToken.KEYWORD, 'BY')
            result['group_by'] = self.consume(PQLToken.IDENTIFIER)[1]
        
        if self.current_token()[1] == 'LIMIT':
            self.consume(PQLToken.KEYWORD, 'LIMIT')
            result['limit'] = int(self.consume(PQLToken.NUMBER)[1])
        
        return result
    
    def parse_aggregate(self):
        """Parse AGGREGATE command"""
        self.consume(PQLToken.KEYWORD, 'AGGREGATE')
        
        source = 'events'
        if self.current_token()[0] == PQLToken.IDENTIFIER:
            source = self.consume(PQLToken.IDENTIFIER)[1]
        
        result = {
            'command': 'AGGREGATE',
            'source': source,
            'group_by': None,
            'aggregations': [],
            'conditions': [],
            'having': None,
            'within': None,
        }
        
        if self.current_token()[1] == 'BY':
            self.consume(PQLToken.KEYWORD, 'BY')
            result['group_by'] = self.consume(PQLToken.IDENTIFIER)[1]
        
        # Parse aggregation function
        if self.current_token()[1] in ('COUNT', 'SUM', 'AVG', 'MIN', 'MAX'):
            func = self.consume(PQLToken.KEYWORD)[1]
            result['aggregations'].append({'function': func})
        
        if self.current_token()[1] == 'WHERE':
            self.consume(PQLToken.KEYWORD, 'WHERE')
            result['conditions'] = self.parse_conditions()
        
        if self.current_token()[1] == 'WITHIN':
            self.consume(PQLToken.KEYWORD, 'WITHIN')
            # Parse time value (e.g., "1h", "24h", "7d") using _parse_value which handles time parsing
            result['within'] = self._parse_value()
        
        return result
    
    def parse_conditions(self):
        """Parse WHERE conditions"""
        conditions = []
        
        while True:
            condition = self.parse_condition()
            conditions.append(condition)
            
            if self.current_token()[0] == PQLToken.LOGICAL:
                logical_op = self.consume(PQLToken.LOGICAL)[1]
                conditions.append({'logical': logical_op})
            else:
                break
        
        return conditions
    
    def parse_condition(self):
        """Parse a single condition"""
        field = self.consume(PQLToken.IDENTIFIER)[1]
        
        token = self.current_token()
        
        if token[0] == PQLToken.COMPARISON:
            operator = self.consume(PQLToken.COMPARISON)[1]
            value = self._parse_value()
            return {'field': field, 'operator': operator, 'value': value}
        
        elif token[1] == 'CONTAINS':
            self.consume(PQLToken.KEYWORD, 'CONTAINS')
            value = self._parse_value()
            return {'field': field, 'operator': 'CONTAINS', 'value': value}
        
        elif token[1] == 'LIKE':
            self.consume(PQLToken.KEYWORD, 'LIKE')
            value = self._parse_value()
            return {'field': field, 'operator': 'LIKE', 'value': value}
        
        elif token[1] == 'IN':
            self.consume(PQLToken.KEYWORD, 'IN')
            self.consume(PQLToken.LPAREN)
            values = []
            while self.current_token()[0] != PQLToken.RPAREN:
                values.append(self._parse_value())
                if self.current_token()[0] == PQLToken.COMMA:
                    self.consume(PQLToken.COMMA)
            self.consume(PQLToken.RPAREN)
            return {'field': field, 'operator': 'IN', 'value': values}
        
        raise PQLSyntaxError(f"Expected operator, got {token}")
    
    def _parse_value(self):
        """Parse a value (string, number, or time expression)"""
        token = self.current_token()
        
        if token[0] == PQLToken.STRING:
            return self.consume(PQLToken.STRING)[1]
        elif token[0] == PQLToken.NUMBER:
            value = self.consume(PQLToken.NUMBER)[1]
            # Parse time expression (e.g., "24h", "7d", "1h")
            if len(value) > 0 and value[-1].lower() in 'hmsdw':
                return self._parse_time_value(value)
            # Regular number
            try:
                return int(value) if '.' not in value else float(value)
            except ValueError:
                raise PQLSyntaxError(f"Invalid number: {value}")
        elif token[0] == PQLToken.IDENTIFIER:
            # Treat identifiers as string values (e.g., CRITICAL, HIGH, etc.)
            return self.consume(PQLToken.IDENTIFIER)[1]
        elif token[1] == 'NOW':
            self.consume(PQLToken.KEYWORD, 'NOW')
            return timezone.now()
        elif token[1] in ('TRUE', 'FALSE'):
            return self.consume(PQLToken.KEYWORD)[1] == 'TRUE'
        elif token[1] == 'NULL':
            self.consume(PQLToken.KEYWORD)
            return None
        
        raise PQLSyntaxError(f"Expected value, got {token}")
    
    def _parse_time_value(self, value):
        """Parse time value like '24h' or '7d' - returns timezone-aware datetime"""
        return parse_time_value(value)


def parse_time_value(value):
    """Standalone function to parse time value like '24h' or '7d' - returns timezone-aware datetime"""
    if not value or len(value) < 2:
        return timezone.now()
    
    unit = value[-1].lower()
    try:
        amount = int(value[:-1])
    except (ValueError, TypeError):
        return timezone.now()
    
    # Get current timezone-aware datetime
    now = timezone.now()
    
    # Calculate the time difference
    if unit == 's':
        delta = timedelta(seconds=amount)
    elif unit == 'm':
        delta = timedelta(minutes=amount)
    elif unit == 'h':
        delta = timedelta(hours=amount)
    elif unit == 'd':
        delta = timedelta(days=amount)
    elif unit == 'w':
        delta = timedelta(weeks=amount)
    else:
        return now
    
    result = now - delta
    
    # Ensure timezone-aware (should already be, but double-check)
    if timezone.is_naive(result):
        result = timezone.make_aware(result)
    
    return result


class PQLExecutor:
    """Executes parsed PQL queries"""
    
    FIELD_MAP = {
        'event_id': 'event_id',
        'timestamp': 'timestamp',
        'hostname': 'hostname',
        'channel': 'channel',
        'severity': 'severity',
        'user_name': 'user_name',
        'user': 'user_name',
        'source_ip': 'source_ip',
        'dest_ip': 'destination_ip',
        'destination_ip': 'destination_ip',
        'process_name': 'process_name',
        'process': 'process_name',
        'process_path': 'process_path',
        'command_line': 'command_line',
        'cmd': 'command_line',
        'service_name': 'service_name',
        'service': 'service_name',
        'message': 'message',
        'msg': 'message',
        'agent_id': 'agent_id',
        'logon_type': 'logon_type',
        'raw_xml': 'raw_xml',
        'xml': 'raw_xml',
        'event_data': 'event_data',
        'data': 'event_data',
        'full_text': 'full_text',
        'text': 'full_text',
    }
    
    # Cache valid fields from SecurityEvent model
    _valid_fields = None
    
    def __init__(self):
        pass
    
    def _get_valid_fields(self):
        """Get list of valid field names from SecurityEvent model"""
        if self._valid_fields is None:
            # Get all field names from SecurityEvent model
            self._valid_fields = set()
            for field in SecurityEvent._meta.get_fields():
                if hasattr(field, 'name'):
                    self._valid_fields.add(field.name)
            # Also include mapped fields
            self._valid_fields.update(self.FIELD_MAP.values())
        return self._valid_fields
    
    def _is_valid_field(self, field_name):
        """Check if a field name is valid for SecurityEvent model"""
        valid_fields = self._get_valid_fields()
        return field_name in valid_fields
    
    def execute(self, ast):
        """Execute a parsed PQL AST"""
        command = ast.get('command')
        
        if command == 'SEARCH':
            return self._execute_search(ast)
        elif command == 'HUNT':
            return self._execute_hunt(ast)
        elif command == 'AGGREGATE':
            return self._execute_aggregate(ast)
        
        raise PQLExecutionError(f"Unknown command: {command}")
    
    def _execute_search(self, ast):
        """Execute SEARCH command"""
        queryset = SecurityEvent.objects.all()
        
        # Apply conditions
        q_objects, has_valid = self._build_q_objects(ast.get('conditions', []))
        if not has_valid:
            # All conditions were invalid fields - return empty result
            queryset = SecurityEvent.objects.none()
        elif q_objects:
            try:
                queryset = queryset.filter(q_objects)
            except Exception as e:
                # If filter fails (e.g., invalid field), return empty queryset
                from django.core.exceptions import FieldError
                if isinstance(e, FieldError):
                    queryset = SecurityEvent.objects.none()
                else:
                    raise
        
        # Apply ordering
        order_by = ast.get('order_by') or 'timestamp'
        order_by = self.FIELD_MAP.get(order_by, order_by) or 'timestamp'
        if ast.get('order_dir') == 'DESC':
            order_by = f'-{order_by}'
        queryset = queryset.order_by(order_by)
        
        # Apply limit
        limit = ast.get('limit', 100)
        offset = ast.get('offset', 0)
        queryset = queryset[offset:offset + limit]
        
        return list(queryset.values())
    
    def _execute_hunt(self, ast):
        """Execute HUNT command (threat hunting)"""
        queryset = SecurityEvent.objects.all()
        
        q_objects, has_valid = self._build_q_objects(ast.get('conditions', []))
        if not has_valid:
            # All conditions were invalid fields - return empty result
            queryset = SecurityEvent.objects.none()
        elif q_objects:
            try:
                queryset = queryset.filter(q_objects)
            except Exception as e:
                # If filter fails (e.g., invalid field), return empty queryset
                from django.core.exceptions import FieldError
                if isinstance(e, FieldError):
                    queryset = SecurityEvent.objects.none()
                else:
                    raise
        
        group_by = ast.get('group_by')
        if group_by:
            group_by = self.FIELD_MAP.get(group_by, group_by)
            queryset = queryset.values(group_by).annotate(
                count=Count('id'),
                first_seen=Min('timestamp'),
                last_seen=Max('timestamp')
            ).order_by('-count')
        
        limit = ast.get('limit', 500)
        return list(queryset[:limit])
    
    def _execute_aggregate(self, ast):
        """Execute AGGREGATE command"""
        queryset = SecurityEvent.objects.all()
        
        # Apply time filter - ensure within is a datetime object
        within = ast.get('within')
        if within:
            # If it's a string (time expression like "1h"), parse it
            if isinstance(within, str):
                within = parse_time_value(within)
            # Ensure timezone-aware datetime
            if isinstance(within, datetime):
                if timezone.is_naive(within):
                    within = timezone.make_aware(within)
                queryset = queryset.filter(timestamp__gte=within)
        
        q_objects = self._build_q_objects(ast.get('conditions', []))
        if q_objects:
            try:
                queryset = queryset.filter(q_objects)
            except Exception as e:
                # If filter fails (e.g., invalid field), return empty queryset
                from django.core.exceptions import FieldError
                if isinstance(e, FieldError):
                    queryset = SecurityEvent.objects.none()
                else:
                    raise
        
        group_by = ast.get('group_by')
        if group_by:
            group_by = self.FIELD_MAP.get(group_by, group_by)
            
            aggregations = ast.get('aggregations', [{'function': 'COUNT'}])
            agg_kwargs = {}
            
            for agg in aggregations:
                func = agg['function']
                if func == 'COUNT':
                    agg_kwargs['count'] = Count('id')
                elif func == 'SUM':
                    agg_kwargs['sum'] = Sum('id')
                elif func == 'AVG':
                    agg_kwargs['avg'] = Avg('id')
                elif func == 'MIN':
                    agg_kwargs['min'] = Min('timestamp')
                elif func == 'MAX':
                    agg_kwargs['max'] = Max('timestamp')
            
            queryset = queryset.values(group_by).annotate(**agg_kwargs).order_by('-count')
        
        return list(queryset[:100])
    
    def _build_q_objects(self, conditions):
        """Build Django Q objects from parsed conditions
        Returns (q_object, has_valid_conditions) tuple
        If has_valid_conditions is False, all conditions were invalid
        """
        if not conditions:
            return None, True
        
        q_result = None
        current_logical = 'AND'
        has_valid_conditions = False
        
        for item in conditions:
            if 'logical' in item:
                current_logical = item['logical']
                continue
            
            field = item['field']
            field = self.FIELD_MAP.get(field, field)
            
            # Validate field exists in model
            if not self._is_valid_field(field):
                # Skip invalid fields
                continue
            
            has_valid_conditions = True
            
            operator = item['operator']
            value = item['value']
            
            # Ensure datetime values are timezone-aware for timestamp fields
            # Django ORM requires timezone-aware datetimes for DateTimeField comparisons
            if field == 'timestamp':
                if isinstance(value, datetime):
                    if timezone.is_naive(value):
                        value = timezone.make_aware(value)
                elif isinstance(value, str):
                    # Check if it's a time expression (e.g., "1h", "24h", "7d")
                    if len(value) > 0 and value[-1].lower() in 'hmsdw':
                        value = parse_time_value(value)
                    else:
                        # Try to parse as ISO datetime string
                        try:
                            from django.utils.dateparse import parse_datetime
                            parsed = parse_datetime(value)
                            if parsed:
                                value = parsed
                                if timezone.is_naive(value):
                                    value = timezone.make_aware(value)
                        except:
                            pass
            
            if operator == '=':
                q = Q(**{field: value})
            elif operator == '!=':
                q = ~Q(**{field: value})
            elif operator == '>':
                q = Q(**{f'{field}__gt': value})
            elif operator == '>=':
                q = Q(**{f'{field}__gte': value})
            elif operator == '<':
                q = Q(**{f'{field}__lt': value})
            elif operator == '<=':
                q = Q(**{f'{field}__lte': value})
            elif operator == 'CONTAINS':
                # For message field, search across multiple text fields for comprehensive results
                if field in ['message', 'msg']:
                    # Search in message, raw_xml, event_data, and full_text fields
                    q = (Q(message__icontains=value) | 
                         Q(raw_xml__icontains=value) | 
                         Q(event_data__icontains=value) |
                         Q(full_text__icontains=value))
                # For JSON fields, search within the JSON structure
                elif field in ['event_data', 'user_data', 'system_data']:
                    # Search in JSON field values
                    q = Q(**{f'{field}__icontains': value})
                else:
                    q = Q(**{f'{field}__icontains': value})
            elif operator == 'LIKE':
                # Convert SQL LIKE to Django regex
                pattern = value.replace('%', '.*').replace('_', '.')
                q = Q(**{f'{field}__regex': pattern})
            elif operator == 'IN':
                q = Q(**{f'{field}__in': value})
            else:
                continue
            
            if q_result is None:
                q_result = q
            elif current_logical == 'AND':
                q_result &= q
            elif current_logical == 'OR':
                q_result |= q
        
        return q_result, has_valid_conditions


def execute_pql(query_string, limit=100):
    """
    Main function to execute a PQL query
    Returns the query results
    
    Args:
        query_string: PQL query string
        limit: Maximum number of results (default 100, max 5000)
    """
    if not query_string or not query_string.strip():
        raise PQLSyntaxError("Empty query string")
    
    # Tokenize
    lexer = PQLLexer(query_string)
    tokens = lexer.tokenize()
    
    # Parse
    parser = PQLParser(tokens)
    ast = parser.parse()
    
    # Override limit if provided and valid
    if limit and isinstance(limit, int) and 1 <= limit <= 5000:
        if 'limit' not in ast or ast.get('limit', 100) > limit:
            ast['limit'] = limit
    
    # Execute
    executor = PQLExecutor()
    results = executor.execute(ast)
    
    return results

