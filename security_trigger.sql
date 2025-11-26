CREATE OR REPLACE TRIGGER AFTER_FAILED_LOGIN
FOR INSERT ON LOGIN_AUDIT
COMPOUND TRIGGER

    TYPE username_table IS TABLE OF VARCHAR2(100) INDEX BY PLS_INTEGER;
    g_failed_usernames username_table;
    g_count NUMBER := 0;

    BEFORE EACH ROW IS
    BEGIN
        IF :NEW.status = 'FAILED' THEN
            g_count := g_count + 1;
            g_failed_usernames(g_count) := :NEW.username;
        END IF;
    END BEFORE EACH ROW;

    AFTER STATEMENT IS
        failed_count NUMBER;
        user_email VARCHAR2(255);
    BEGIN
        user_email := 'security-team@yourcompany.com';
        
        
        FOR i IN 1..g_count LOOP
          
            SELECT COUNT(*)
            INTO failed_count
            FROM login_audit
            WHERE username = g_failed_usernames(i)
              AND status = 'FAILED'
              AND attempt_time >= SYSTIMESTAMP - INTERVAL '1' DAY;
            
            DBMS_OUTPUT.PUT_LINE('Security Check: User ' || g_failed_usernames(i) || 
                               ' has ' || failed_count || ' failed attempts in last 24 hours');
            
            -- If 3 or more failed attempts, create security alert
            IF failed_count >= 3 THEN
                DBMS_OUTPUT.PUT_LINE('ALERT: Creating security alert for ' || g_failed_usernames(i));
                
                INSERT INTO security_alerts (
                    alert_id,
                    Username,
                    Number_of_failed_attemps,
                    Alert_time,
                    Alert_message,
                    Email
                ) VALUES (
                    security_alerts_seq.NEXTVAL,
                    g_failed_usernames(i),
                    failed_count,
                    SYSDATE,
                    'Suspicious login activity detected: ' || failed_count ||
                    ' failed attempts for user ' || g_failed_usernames(i) ||
                    ' within 24 hours. Investigation required.',
                    user_email
                );
                
                DBMS_OUTPUT.PUT_LINE('Security alert created successfully for user: ' || g_failed_usernames(i));
            END IF;
        END LOOP;
        
       
        g_count := 0;
        
    EXCEPTION
        WHEN OTHERS THEN
            DBMS_OUTPUT.PUT_LINE('Error in security trigger: ' || SQLERRM);
        
    END AFTER STATEMENT;
    
END AFTER_FAILED_LOGIN;
/

-- Verify trigger creation
SELECT trigger_name, trigger_type, status 
FROM user_triggers 
WHERE trigger_name = 'AFTER_FAILED_LOGIN';

-- Display trigger source code
SELECT text 
FROM user_source 
WHERE name = 'AFTER_FAILED_LOGIN' 
ORDER BY line;
