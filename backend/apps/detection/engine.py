"""
Dark Knight Phantom SIEM - Detection Engine
Core detection logic with behavioral analysis
"""
from django.utils import timezone
from django.db import transaction, models
from datetime import timedelta, datetime
from typing import List, Dict, Optional, Any
import logging
import re

from .models import DetectionRule, DetectionAlert, EntityTracker, AlertSuppressionRule
from apps.events.models import SecurityEvent

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Main detection engine - evaluates events against rules
    """
    
    # System accounts to exclude from user-based detections
    SYSTEM_ACCOUNTS = {
        'system', 'local service', 'network service', 'anonymous logon',
        'nt authority\\system', 'nt authority\\local service', 
        'nt authority\\network service', 'window manager\\dwm-1',
        'window manager\\dwm-2', 'window manager\\dwm-3',
        'font driver host\\umfd-0', 'font driver host\\umfd-1',
        'font driver host\\umfd-2', 'font driver host\\umfd-3',
        '$', '-', '', 'n/a', 'none',  # Machine accounts end with $, or are just - or empty
        'defaultaccount', 'guest', 'wdagutilityaccount',
        # Common service accounts
        'svc_', 'service_', 'sql', 'iis', 'scom', 'exchange', 'backup',
    }
    
    # Event IDs that are normal system noise - don't track these for user behavior
    NOISE_EVENT_IDS = {
        4798,  # Local group membership was enumerated - happens constantly
        4799,  # Security-enabled local group membership was enumerated
        5320,  # Network driver configuration
        5351,  # NDIS filter driver configuration  
        5117,  # WMI operations
        4117,  # WMI operations
        5857,  # WMI provider loaded
        7040,  # Service state changed - normal system operations
    }
    
    # Known safe service paths
    SAFE_SERVICE_PATHS = [
        r'c:\\windows\\',
        r'c:\\program files\\',
        r'c:\\program files (x86)\\',
        r'c:\\programdata\\microsoft\\',
    ]
    
    def __init__(self):
        self.rules = {}
        self.load_rules()
    
    def load_rules(self):
        """Load all enabled detection rules"""
        self.rules = {
            str(rule.id): rule 
            for rule in DetectionRule.objects.filter(enabled=True)
        }
        logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def is_system_account(self, user_name: str) -> bool:
        """Check if account is a system/service account"""
        if not user_name:
            return True
        user_lower = user_name.lower().strip()
        
        # Exact matches
        if user_lower in self.SYSTEM_ACCOUNTS:
            return True
        
        # Machine accounts end with $
        if user_lower.endswith('$'):
            return True
        
        # DWM and UMFD are display/font driver hosts
        if user_lower.startswith('dwm-') or user_lower.startswith('umfd-'):
            return True
        
        # Contains domain\system patterns
        if 'nt authority' in user_lower or 'nt service' in user_lower:
            return True
        if 'window manager' in user_lower or 'font driver' in user_lower:
            return True
        
        # Service account naming conventions
        if user_lower.startswith('svc_') or user_lower.startswith('svc-'):
            return True
        if user_lower.startswith('service_') or user_lower.startswith('service-'):
            return True
        
        return False
    
    def get_or_create_tracker(
        self, 
        entity_type: str, 
        entity_value: str, 
        hostname: str = '',
        window_minutes: int = 10,
        event_time: datetime = None
    ) -> EntityTracker:
        """Get or create entity tracker for time window based on event time"""
        # Use event time if provided, otherwise use now
        reference_time = event_time if event_time else timezone.now()
        window_start = reference_time - timedelta(minutes=window_minutes)
        
        # Clean up old trackers periodically (1 hour old)
        cleanup_threshold = timezone.now() - timedelta(hours=1)
        EntityTracker.objects.filter(window_end__lt=cleanup_threshold).delete()
        
        # Look for existing tracker that overlaps with our window
        tracker = EntityTracker.objects.filter(
            entity_type=entity_type,
            entity_value=entity_value,
            hostname=hostname,
            window_end__gte=window_start  # Tracker that's still active for our window
        ).first()
        
        if tracker:
            # Extend window if needed
            if reference_time > tracker.window_end:
                tracker.window_end = reference_time + timedelta(minutes=window_minutes)
                tracker.save(update_fields=['window_end'])
            return tracker
        
        # Create new tracker
        tracker = EntityTracker.objects.create(
            entity_type=entity_type,
            entity_value=entity_value,
            hostname=hostname,
            window_start=reference_time,
            window_end=reference_time + timedelta(minutes=window_minutes),
            event_counts={},
            unique_values={},
            event_ids=[],
        )
        
        return tracker
    
    def check_suppression(self, rule: DetectionRule, event: SecurityEvent) -> bool:
        """Check if alert should be suppressed"""
        suppressions = AlertSuppressionRule.objects.filter(
            enabled=True,
            detection_rule=rule
        ).filter(
            models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
        )
        
        for suppression in suppressions:
            conditions = suppression.conditions
            match = True
            for field, pattern in conditions.items():
                event_value = getattr(event, field, None)
                if event_value:
                    if isinstance(pattern, list):
                        if str(event_value).lower() not in [p.lower() for p in pattern]:
                            match = False
                            break
                    elif not re.match(pattern, str(event_value), re.IGNORECASE):
                        match = False
                        break
            if match:
                return True
        return False
    
    def check_cooldown(self, rule: DetectionRule, entity_key: str, entity_type: str) -> bool:
        """Check if rule is in cooldown for this entity"""
        if rule.cooldown_minutes <= 0:
            return False
        
        cooldown_start = timezone.now() - timedelta(minutes=rule.cooldown_minutes)
        
        # Build query based on entity type to avoid type mismatch errors
        base_query = DetectionAlert.objects.filter(
            rule=rule,
            triggered_at__gte=cooldown_start
        )
        
        if entity_type in ['USER_NAME', 'TARGET_USER']:
            recent_alert = base_query.filter(
                models.Q(user_name=entity_key) | models.Q(target_user=entity_key)
            ).exists()
        elif entity_type == 'SOURCE_IP':
            try:
                recent_alert = base_query.filter(source_ip=entity_key).exists()
            except:
                recent_alert = False
        elif entity_type == 'HOSTNAME':
            recent_alert = base_query.filter(hostname=entity_key).exists()
        else:
            recent_alert = base_query.filter(
                models.Q(user_name=entity_key) | models.Q(hostname=entity_key)
            ).exists()
        
        return recent_alert
    
    def create_alert(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        tracker: EntityTracker,
        title: str,
        description: str,
        confidence: int = 80,
        extra_evidence: dict = None
    ) -> Optional[DetectionAlert]:
        """Create a detection alert"""
        
        # Check cooldown
        entity_key = tracker.entity_value
        if self.check_cooldown(rule, entity_key, tracker.entity_type):
            logger.debug(f"Rule {rule.name} in cooldown for {entity_key}")
            return None
        
        # Check confidence threshold
        if confidence < rule.min_confidence:
            logger.debug(f"Confidence {confidence} below threshold {rule.min_confidence}")
            return None
        
        evidence = {
            'event_counts': tracker.event_counts,
            'unique_values': tracker.unique_values,
            'triggering_event_id': event.event_id,
            'window_minutes': (tracker.window_end - tracker.window_start).seconds // 60,
        }
        if extra_evidence:
            evidence.update(extra_evidence)
        
        alert = DetectionAlert.objects.create(
            rule=rule,
            title=title,
            description=description,
            severity=rule.severity,
            hostname=event.hostname,
            user_name=event.user_name or event.target_user_name or '',
            source_ip=event.source_ip,
            target_user=event.target_user_name or '',
            matched_events=tracker.event_ids[-50:],  # Last 50 events
            event_count=tracker.get_total_count(),
            evidence=evidence,
            confidence=confidence,
            first_event_time=tracker.window_start,
            last_event_time=event.timestamp,
        )
        
        # Update rule statistics
        rule.total_alerts += 1
        rule.save(update_fields=['total_alerts'])
        
        logger.warning(f"🚨 ALERT: [{rule.severity}] {title} - {entity_key}")
        return alert
    
    def process_event(self, event: SecurityEvent) -> List[DetectionAlert]:
        """Process a single event against all rules"""
        alerts = []
        
        # Skip noise events that are just normal system operations
        if event.event_id in self.NOISE_EVENT_IDS:
            return alerts
        
        # Skip events from system accounts for user-based rules
        is_system = self.is_system_account(event.user_name)
        is_target_system = self.is_system_account(event.target_user_name)
        
        for rule_id, rule in self.rules.items():
            try:
                alert = self.evaluate_rule(rule, event, is_system, is_target_system)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")
        
        return alerts
    
    def evaluate_rule(
        self, 
        rule: DetectionRule, 
        event: SecurityEvent,
        is_system_account: bool = False,
        is_target_system_account: bool = False
    ) -> Optional[DetectionAlert]:
        """Evaluate a single rule against an event"""
        logic = rule.logic
        
        # Check if event ID matches rule
        event_ids = logic.get('event_ids', [])
        if event_ids and event.event_id not in event_ids:
            return None
        
        # Skip system accounts for user-focused rules
        if logic.get('exclude_system_accounts', True):
            if is_system_account and is_target_system_account:
                return None
            # For target_user based tracking, check target account
            track_by = logic.get('track_by', 'user_name')
            if track_by == 'target_user' and is_target_system_account:
                return None
            if track_by == 'user_name' and is_system_account:
                return None
        
        # Get tracker settings
        track_by = logic.get('track_by', 'user_name')
        window_minutes = logic.get('window_minutes', 10)
        
        # Get entity value to track
        entity_value = self._get_entity_value(event, track_by)
        if not entity_value:
            return None
        
        # Get or create tracker - use event timestamp for window
        tracker = self.get_or_create_tracker(
            entity_type=track_by.upper(),
            entity_value=entity_value,
            hostname=event.hostname,
            window_minutes=window_minutes,
            event_time=event.timestamp
        )
        
        # Update tracker
        tracker.increment_event(event.event_id, event.id)
        tracker.last_event_time = event.timestamp
        
        # Track unique values if specified
        for field in logic.get('track_unique', []):
            value = getattr(event, field, None)
            if value:
                tracker.add_unique_value(field, str(value))
        
        tracker.save()
        
        # Evaluate based on rule type
        if rule.rule_type == 'THRESHOLD':
            return self._evaluate_threshold(rule, event, tracker)
        elif rule.rule_type == 'SEQUENCE':
            return self._evaluate_sequence(rule, event, tracker)
        elif rule.rule_type == 'PATTERN':
            return self._evaluate_pattern(rule, event, tracker)
        elif rule.rule_type == 'CORRELATION':
            return self._evaluate_correlation(rule, event, tracker)
        
        return None
    
    def _get_entity_value(self, event: SecurityEvent, track_by: str) -> Optional[str]:
        """Get entity value from event based on tracking field"""
        if track_by == 'user_name':
            return event.user_name or event.target_user_name
        elif track_by == 'source_ip':
            return str(event.source_ip) if event.source_ip else None
        elif track_by == 'hostname':
            return event.hostname
        elif track_by == 'target_user':
            return event.target_user_name
        elif track_by == 'process':
            return event.process_name
        elif track_by == 'service':
            return event.service_name
        return getattr(event, track_by, None)
    
    def _evaluate_threshold(
        self, 
        rule: DetectionRule, 
        event: SecurityEvent, 
        tracker: EntityTracker
    ) -> Optional[DetectionAlert]:
        """Evaluate threshold-based rule"""
        logic = rule.logic
        threshold = logic.get('threshold', 5)
        event_ids = logic.get('event_ids', [event.event_id])
        
        count = tracker.get_total_count(event_ids)
        
        if count >= threshold:
            # Additional conditions
            if 'unique_threshold' in logic:
                unique_field = logic['unique_threshold']['field']
                unique_min = logic['unique_threshold']['min']
                if tracker.get_unique_count(unique_field) < unique_min:
                    return None
            
            confidence = min(100, 50 + (count - threshold) * 10)
            
            return self.create_alert(
                rule=rule,
                event=event,
                tracker=tracker,
                title=f"{rule.name}: {tracker.entity_value}",
                description=f"Detected {count} events (threshold: {threshold}) for {tracker.entity_type} '{tracker.entity_value}' within {logic.get('window_minutes', 10)} minutes",
                confidence=confidence,
            )
        
        return None
    
    def _evaluate_sequence(
        self, 
        rule: DetectionRule, 
        event: SecurityEvent, 
        tracker: EntityTracker
    ) -> Optional[DetectionAlert]:
        """Evaluate sequence-based rule (e.g., failed logins then success)"""
        logic = rule.logic
        sequence = logic.get('sequence', [])
        
        if len(sequence) < 2:
            return None
        
        # Check if sequence conditions are met
        all_conditions_met = True
        for step in sequence:
            step_event_ids = step.get('event_ids', [step.get('event_id')])
            step_count = step.get('count', 1)
            
            actual_count = sum(tracker.get_event_count(eid) for eid in step_event_ids if eid)
            if actual_count < step_count:
                all_conditions_met = False
                break
        
        if all_conditions_met:
            # Check if the final event is the trigger
            final_step = sequence[-1]
            final_event_ids = final_step.get('event_ids', [final_step.get('event_id')])
            if event.event_id not in final_event_ids:
                return None
            
            confidence = 85
            
            return self.create_alert(
                rule=rule,
                event=event,
                tracker=tracker,
                title=f"{rule.name}: {tracker.entity_value}",
                description=f"Detected suspicious sequence for {tracker.entity_type} '{tracker.entity_value}': {tracker.event_counts}",
                confidence=confidence,
            )
        
        return None
    
    def _evaluate_pattern(
        self, 
        rule: DetectionRule, 
        event: SecurityEvent, 
        tracker: EntityTracker
    ) -> Optional[DetectionAlert]:
        """Evaluate pattern-based rule (specific field values)"""
        logic = rule.logic
        patterns = logic.get('patterns', {})
        
        matches = 0
        for field, pattern in patterns.items():
            event_value = getattr(event, field, None)
            if event_value:
                if isinstance(pattern, list):
                    if any(p.lower() in str(event_value).lower() for p in pattern):
                        matches += 1
                elif re.search(pattern, str(event_value), re.IGNORECASE):
                    matches += 1
        
        required_matches = logic.get('required_matches', len(patterns))
        
        if matches >= required_matches:
            confidence = min(100, 70 + matches * 10)
            
            return self.create_alert(
                rule=rule,
                event=event,
                tracker=tracker,
                title=f"{rule.name}: {event.hostname}",
                description=f"Detected suspicious pattern: {matches}/{len(patterns)} conditions matched",
                confidence=confidence,
                extra_evidence={'matched_patterns': matches}
            )
        
        return None
    
    def _evaluate_correlation(
        self, 
        rule: DetectionRule, 
        event: SecurityEvent, 
        tracker: EntityTracker
    ) -> Optional[DetectionAlert]:
        """Evaluate correlation rule (multiple event types together)"""
        logic = rule.logic
        required_events = logic.get('required_events', [])
        
        # Check if all required event types are present
        present_events = set(int(k) for k in tracker.event_counts.keys())
        required_set = set(required_events)
        
        if required_set.issubset(present_events):
            # Check minimum counts if specified
            min_counts = logic.get('min_counts', {})
            all_counts_met = True
            for eid, min_count in min_counts.items():
                if tracker.get_event_count(int(eid)) < min_count:
                    all_counts_met = False
                    break
            
            if all_counts_met:
                confidence = 90
                
                return self.create_alert(
                    rule=rule,
                    event=event,
                    tracker=tracker,
                    title=f"{rule.name}: {tracker.entity_value}",
                    description=f"Detected correlated events: {list(required_set)} for '{tracker.entity_value}'",
                    confidence=confidence,
                )
        
        return None


# Singleton instance
_engine = None

def get_engine() -> DetectionEngine:
    """Get singleton detection engine instance"""
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine


def process_event_detection(event: SecurityEvent) -> List[DetectionAlert]:
    """Process event through detection engine"""
    engine = get_engine()
    return engine.process_event(event)


def reload_rules():
    """Reload detection rules"""
    global _engine
    if _engine:
        _engine.load_rules()

