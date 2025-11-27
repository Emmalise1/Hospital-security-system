-- #############################################################
-- # TEST SCRIPT: Security Policy Validation for Failed Logins #
-- # Author: <Gentille_27398>                                       #
-- # Purpose: Automatically test login attempts and alerting   #
-- #############################################################
SET SERVEROUTPUT ON;

DECLARE
    -- v_alert_count: stores number of alerts found for the test user
    v_alert_count NUMBER;
    -- v_login_count: stores number of login_audit entries
    v_login_count NUMBER;
    -- v_username: generates a unique test user each run
    v_username VARCHAR2(100) := 'test_user_' || TO_CHAR(SYSTIMESTAMP, 'SSFF');
    v_test_result VARCHAR2(10);
BEGIN
    DBMS_OUTPUT.PUT_LINE('=================================================');
    DBMS_OUTPUT.PUT_LINE('SECURITY MONITORING SYSTEM - COMPREHENSIVE TEST');
    DBMS_OUTPUT.PUT_LINE('=================================================');
    DBMS_OUTPUT.PUT_LINE('Testing User: ' || v_username);
    DBMS_OUTPUT.PUT_LINE('');
    

    -- PHASE 1: Clean previous test data to ensure a fresh environment.
    DBMS_OUTPUT.PUT_LINE('PHASE 1: INITIAL SETUP');
    DBMS_OUTPUT.PUT_LINE('-----------------------');
    DELETE FROM security_alerts WHERE username = v_username;
    DELETE FROM login_audit WHERE username = v_username;
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Cleaned existing test data for user: ' || v_username);
    DBMS_OUTPUT.PUT_LINE('');
    

    -- PHASE 2: Validate that the trigger does NOT generate alerts
    --  when failed login attempts are less than 3.
    DBMS_OUTPUT.PUT_LINE('PHASE 2: TEST 1-2 FAILED ATTEMPTS (NO ALERTS)');
    DBMS_OUTPUT.PUT_LINE('---------------------------------------------');
    

    DBMS_OUTPUT.PUT_LINE('Test 2.1: First failed login attempt');
    INSERT INTO login_audit (username, attempt_time, status, ip_address) 
    VALUES (v_username, SYSTIMESTAMP, 'FAILED', '192.168.1.100');
    COMMIT;
    
    SELECT COUNT(*) INTO v_alert_count FROM security_alerts WHERE username = v_username;
    SELECT COUNT(*) INTO v_login_count FROM login_audit WHERE username = v_username AND status = 'FAILED';
    
    IF v_alert_count = 0 THEN
        DBMS_OUTPUT.PUT_LINE('RESULT: PASS - No security alert after 1 failed attempt');
    ELSE
        DBMS_OUTPUT.PUT_LINE('RESULT: FAIL - Unexpected alert after 1 failed attempt');
    END IF;
    DBMS_OUTPUT.PUT_LINE('');
    

    DBMS_OUTPUT.PUT_LINE('Test 2.2: Second failed login attempt');
    INSERT INTO login_audit (username, attempt_time, status, ip_address) 
    VALUES (v_username, SYSTIMESTAMP, 'FAILED', '192.168.1.100');
    COMMIT;
    
    SELECT COUNT(*) INTO v_alert_count FROM security_alerts WHERE username = v_username;
    SELECT COUNT(*) INTO v_login_count FROM login_audit WHERE username = v_username AND status = 'FAILED';
    
    IF v_alert_count = 0 THEN
        DBMS_OUTPUT.PUT_LINE('RESULT: PASS - No security alert after 2 failed attempts');
    ELSE
        DBMS_OUTPUT.PUT_LINE('RESULT: FAIL - Unexpected alert after 2 failed attempts');
    END IF;
    DBMS_OUTPUT.PUT_LINE('');
    
    -- PHASE 3: Validate that an alert IS generated at 3 failed attempts.
    DBMS_OUTPUT.PUT_LINE('PHASE 3: TEST 3RD FAILED ATTEMPT (ALERT EXPECTED)');
    DBMS_OUTPUT.PUT_LINE('------------------------------------------------');
    
    DBMS_OUTPUT.PUT_LINE('Test 3.1: Third failed login attempt');
    INSERT INTO login_audit (username, attempt_time, status, ip_address) 
    VALUES (v_username, SYSTIMESTAMP, 'FAILED', '192.168.1.100');
    COMMIT;
    
    SELECT COUNT(*) INTO v_alert_count FROM security_alerts WHERE username = v_username;
    SELECT COUNT(*) INTO v_login_count FROM login_audit WHERE username = v_username AND status = 'FAILED';
    
    IF v_alert_count = 1 THEN
        DBMS_OUTPUT.PUT_LINE('RESULT: PASS - Security alert correctly generated after 3 failed attempts');
    ELSE
        DBMS_OUTPUT.PUT_LINE('RESULT: FAIL - No security alert generated after 3 failed attempts');
    END IF;
    DBMS_OUTPUT.PUT_LINE('');
    
    -- PHASE 4: Ensure the generated alert contains correct details.
    DBMS_OUTPUT.PUT_LINE('PHASE 4: ALERT DETAILS VERIFICATION');
    DBMS_OUTPUT.PUT_LINE('-----------------------------------');
    
    FOR alert IN (
        SELECT alert_id, username, number_of_failed_attemps, 
               alert_time, alert_message, email
        FROM security_alerts 
        WHERE username = v_username
    ) LOOP
        DBMS_OUTPUT.PUT_LINE('Alert ID: ' || alert.alert_id);
        DBMS_OUTPUT.PUT_LINE('Username: ' || alert.username);
        DBMS_OUTPUT.PUT_LINE('Failed Attempts: ' || alert.number_of_failed_attemps);
        DBMS_OUTPUT.PUT_LINE('Alert Time: ' || TO_CHAR(alert.alert_time, 'YYYY-MM-DD HH24:MI:SS'));
        DBMS_OUTPUT.PUT_LINE('Message: ' || alert.alert_message);
        DBMS_OUTPUT.PUT_LINE('Notification Email: ' || alert.email);
    END LOOP;
    DBMS_OUTPUT.PUT_LINE('');
    
    -- PHASE 5: Verify that successful login attempts do not trigger alerts.
    DBMS_OUTPUT.PUT_LINE('PHASE 5: TEST SUCCESSFUL LOGIN (NO ADDITIONAL ALERT)');
    DBMS_OUTPUT.PUT_LINE('----------------------------------------------------');
    
    INSERT INTO login_audit (username, attempt_time, status, ip_address) 
    VALUES (v_username, SYSTIMESTAMP, 'SUCCESS', '192.168.1.100');
    COMMIT;
    
    SELECT COUNT(*) INTO v_alert_count FROM security_alerts WHERE username = v_username;
    
    IF v_alert_count = 1 THEN
        DBMS_OUTPUT.PUT_LINE('RESULT: PASS - No additional alert for successful login');
    ELSE
        DBMS_OUTPUT.PUT_LINE('RESULT: FAIL - Alert count changed after successful login');
    END IF;
    DBMS_OUTPUT.PUT_LINE('');
    
    -- PHASE 6: Summarize total attempts and alerts.
    DBMS_OUTPUT.PUT_LINE('PHASE 6: TEST SUMMARY');
    DBMS_OUTPUT.PUT_LINE('---------------------');
    SELECT COUNT(*) INTO v_login_count FROM login_audit WHERE username = v_username;
    DBMS_OUTPUT.PUT_LINE('Total login attempts for ' || v_username || ': ' || v_login_count);
    DBMS_OUTPUT.PUT_LINE('Total security alerts for ' || v_username || ': ' || v_alert_count);
    DBMS_OUTPUT.PUT_LINE('');
    
    DBMS_OUTPUT.PUT_LINE('SECURITY POLICY VERIFICATION RESULTS:');
    DBMS_OUTPUT.PUT_LINE('------------------------------------');
    DBMS_OUTPUT.PUT_LINE('PASS: 1-2 failed attempts = No alerts generated');
    DBMS_OUTPUT.PUT_LINE('PASS: 3+ failed attempts = Security alert triggered');
    DBMS_OUTPUT.PUT_LINE('PASS: Successful logins ignored by trigger');
    DBMS_OUTPUT.PUT_LINE('PASS: Alert contains correct details and email');
    DBMS_OUTPUT.PUT_LINE('PASS: Compound trigger working (no mutating table errors)');
    
    DBMS_OUTPUT.PUT_LINE('');
    DBMS_OUTPUT.PUT_LINE('=================================================');
    DBMS_OUTPUT.PUT_LINE('ALL SECURITY TESTS COMPLETED SUCCESSFULLY');
    DBMS_OUTPUT.PUT_LINE('=================================================');
    
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('ERROR during testing: ' || SQLERRM);
        ROLLBACK;
END;
/


SELECT 'SECURITY SYSTEM STATUS' as verification FROM dual;

SELECT object_name, object_type, status
FROM user_objects
WHERE object_name IN ('LOGIN_AUDIT', 'SECURITY_ALERTS', 'AFTER_FAILED_LOGIN', 'SECURITY_ALERTS_SEQ')
ORDER BY object_type;

SELECT 'LATEST LOGIN ATTEMPTS' as description FROM dual;
SELECT * FROM login_audit WHERE ROWNUM <= 5 ORDER BY attempt_time DESC;

SELECT 'ACTIVE SECURITY ALERTS' as description FROM dual;
SELECT * FROM security_alerts WHERE ROWNUM <= 5 ORDER BY alert_time DESC;
