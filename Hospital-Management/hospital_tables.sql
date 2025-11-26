CREATE TABLE patients (
    patient_id NUMBER PRIMARY KEY,
    patient_name VARCHAR2(100) NOT NULL,
    age NUMBER NOT NULL,
    gender VARCHAR2(10),
    admitted VARCHAR2(1) DEFAULT 'N',
    created_date DATE DEFAULT SYSDATE
);

ALTER TABLE patients ADD CONSTRAINT chk_patient_gender 
CHECK (gender IN ('Male', 'Female', 'Other'));

ALTER TABLE patients ADD CONSTRAINT chk_patient_admitted 
CHECK (admitted IN ('Y', 'N'));

CREATE TABLE doctors (
    doctor_id NUMBER PRIMARY KEY,
    doctor_name VARCHAR2(100) NOT NULL,
    specialty VARCHAR2(100) NOT NULL,
    created_date DATE DEFAULT SYSDATE
);

CREATE SEQUENCE patient_seq START WITH 1 INCREMENT BY 1;
CREATE SEQUENCE doctor_seq START WITH 1 INCREMENT BY 1;

-- Display table structure for verification
DESC patients;
DESC doctors;

-- Verify sequences were created
SELECT sequence_name, last_number FROM user_sequences 
WHERE sequence_name IN ('PATIENT_SEQ', 'DOCTOR_SEQ');

-- Verify constraints were applied
SELECT table_name, constraint_name, constraint_type, search_condition
FROM user_constraints 
WHERE table_name IN ('PATIENTS', 'DOCTORS');
