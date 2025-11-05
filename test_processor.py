# test_processor.py
import pytest
from app import app, db, LogEntry, Device, Alert, LogProcessor # Import necessary classes
from datetime import datetime

# --- Fixture for In-Memory Database and App Context ---

@pytest.fixture(scope='module')
def client():
    """Sets up a testing client with an in-memory SQLite database and test device."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        
        # Add a required test device (Setup once for the module)
        test_device = Device(deviceName='Test-Device-Processor', deviceType='server', ipAddress='10.0.0.5')
        db.session.add(test_device)
        db.session.commit()
        app.config['TEST_PROCESSOR_DEVICE_ID'] = test_device.deviceID
        
        with app.test_client() as client:
            yield client # Run the tests
        
        # Clean up database after all tests in the module are finished
        db.session.remove()
        db.drop_all()

# --- Tests for LogProcessor Class ---

def test_processor_high_severity_flagging_branch(client):
    """
    Test 1: Tests the primary branch where severity >= 'error' flags the log and creates an alert.
    Covers LogProcessor lines: 540-555
    """
    device_id = app.config['TEST_PROCESSOR_DEVICE_ID']
    
    with app.app_context():
        log_entry = LogEntry(
            sourceDevice=device_id,
            severity='critical', # Highest severity to ensure it triggers
            message='System failure: EMERGENCY'
        )
        db.session.add(log_entry)
        db.session.commit() # Commit to get LogID

        LogProcessor.process_log(log_entry)
        
        # Query immediately after processing (it should be committed by LogProcessor)
        alert = Alert.query.filter_by(logID=log_entry.LogID).first()
        
        # --- CRITICAL ASSERTION ADDED: Ensure alert object exists ---
        assert alert is not None
        
        # Assert the high-severity flag branch was taken
        assert log_entry.isFlagged is True
        assert log_entry.status == 'flagged'
        assert alert.alertType == 'High Severity Log'
        assert alert.severity == 'CRITICAL' 
        
        # Clean up this specific entry
        db.session.delete(alert)
        db.session.delete(log_entry)
        db.session.commit()


def test_processor_threat_pattern_flagging_branch(client):
    """
    Test 2: Tests the threat pattern detection and severity escalation branch.
    Covers LogProcessor lines: 559-575
    """
    device_id = app.config['TEST_PROCESSOR_DEVICE_ID']
    
    with app.app_context():
        # Use low severity 'info' to skip the initial high-severity check
        log_entry = LogEntry(
            sourceDevice=device_id,
            severity='info',
            message='Multiple connection refused from 10.0.0.200' # Matches 'Connection_refused'
        )
        db.session.add(log_entry)
        db.session.commit() # Commit to get LogID
        
        LogProcessor.process_log(log_entry)
        
        # Query immediately after processing (it should be committed by LogProcessor)
        alert = Alert.query.filter_by(logID=log_entry.LogID).first()
        
        # --- CRITICAL ASSERTION ADDED: This is what failed previously ---
        assert alert is not None
        
        # Assert the threat-pattern branch was taken
        assert log_entry.isFlagged is True
        assert log_entry.status == 'flagged'

        # Assert alert was created with correct type and escalation
        assert alert.alertType == 'Connection_refused'
        assert alert.severity == 'HIGH' # Severity should be escalated by threat mapping
        
        # Clean up this specific entry
        db.session.delete(alert)
        db.session.delete(log_entry)
        db.session.commit()


def test_processor_no_flagging_analyzed_branch(client):
    """
    Test 3: Tests the final 'else' branch where no flags are set, resulting in 'analyzed' status.
    Covers LogProcessor lines: 577-580
    """
    device_id = app.config['TEST_PROCESSOR_DEVICE_ID']
    
    with app.app_context():
        # Log with 'info' severity and NO threat keywords
        log_entry = LogEntry(
            sourceDevice=device_id,
            severity='info',
            message='Regular system heartbeat OK'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        LogProcessor.process_log(log_entry)
        
        assert log_entry.isFlagged is False
        assert log_entry.status == 'analyzed'
        
        # Assert no alert was created
        alert_count = Alert.query.filter_by(logID=log_entry.LogID).count()
        assert alert_count == 0
        
        # Clean up this specific entry
        db.session.delete(log_entry)
        db.session.commit()

# --- Tests for Internal Helper Methods ---

def test_processor_determine_severity_escalation_logic():
    """
    Test 4: Tests the internal severity escalation logic branches for full coverage.
    Covers LogProcessor lines: 590-600 (all branches of _determine_severity)
    """
    # 1. Base is MEDIUM ('Failed_login') -> Log is ERROR -> Should escalate to HIGH
    severity_high = LogProcessor._determine_severity('Failed_login', 'ERROR')
    assert severity_high == 'HIGH'

    # 2. Base is CRITICAL ('Brute_force') -> Log is INFO -> Stays CRITICAL (highest of base)
    severity_critical = LogProcessor._determine_severity('Brute_force', 'info')
    assert severity_critical == 'CRITICAL'
    
    # 3. Base is MEDIUM ('Suspicious_activity') -> Log is WARNING -> Stays MEDIUM (log severity not high enough to escalate)
    severity_medium = LogProcessor._determine_severity('Suspicious_activity', 'warning')
    assert severity_medium == 'MEDIUM'

    # 4. Edge case: Unknown threat -> Should fall back to the base 'LOW' 
    severity_low = LogProcessor._determine_severity('Unknown_Threat', 'info')
    assert severity_low == 'LOW'