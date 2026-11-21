-- Sandbox extension for ADR 0005 (connector-protocol sign-in).
--
-- Run ONCE as ACCOUNTADMIN on the sandbox account (Snowsight worksheet "Run all", or
-- `snow sql -f`). Before running, set the two values marked EDIT below to the user and role your
-- tests and benchmarks sign in as (the values you export as SNOWFLAKE_USER and SNOWFLAKE_ROLE).
--
-- It creates or updates, idempotently:
--   1. database SNOW_RS_CLI_ADMIN, schema POLICIES (they hold only the two policies below);
--   2. authentication policy PASSWORD_TEST_POLICY: password sign-in only, MFA enrolment optional;
--   3. user SNOW_RS_CLI_PASSWORD_TEST (TYPE = PERSON, role PUBLIC, no warehouse, no grants) with a
--      random password and that policy;
--   4. authentication policy AGENT_PAT_POLICY on the test user: every sign-in method stays
--      allowed (the key pair keeps working); a PAT may be used without a network policy;
--   5. PAT SNOW_RS_CLI_TESTS on the test user, restricted to the test role, 365 days.
--
-- The last result is a table of env-var names and values. Export them in the environment your live tests and benchmarks run in
-- (see ADR 0005, "Sandbox extension"). The password and the PAT are shown only here.
-- Running the script again converges to the same objects and ROTATES the password and the PAT:
-- update those variables after every run. It stops without changing the test user if that user
-- already has another authentication policy (replacing it could lock that user out).

USE ROLE ACCOUNTADMIN;

CREATE DATABASE IF NOT EXISTS SNOW_RS_CLI_ADMIN
  COMMENT = 'snowflake-rs-cli sandbox: authentication policies for tests (ADR 0005)';
CREATE SCHEMA IF NOT EXISTS SNOW_RS_CLI_ADMIN.POLICIES;

CREATE OR ALTER AUTHENTICATION POLICY SNOW_RS_CLI_ADMIN.POLICIES.PASSWORD_TEST_POLICY
  AUTHENTICATION_METHODS = ('PASSWORD')
  MFA_ENROLLMENT = 'OPTIONAL'
  COMMENT = 'snowflake-rs-cli: password sign-in tests without MFA (ADR 0005)';

CREATE OR ALTER AUTHENTICATION POLICY SNOW_RS_CLI_ADMIN.POLICIES.AGENT_PAT_POLICY
  PAT_POLICY = (
    MAX_EXPIRY_IN_DAYS = 365
    NETWORK_POLICY_EVALUATION = ENFORCED_NOT_REQUIRED
  )
  COMMENT = 'snowflake-rs-cli: lets the test user sign in with a PAT without a network policy (ADR 0005)';

EXECUTE IMMEDIATE $$
DECLARE
  agent_user VARCHAR DEFAULT 'EDIT_ME_AGENT_USER';  -- EDIT: value of SNOWFLAKE_USER
  agent_role VARCHAR DEFAULT 'EDIT_ME_AGENT_ROLE';  -- EDIT: value of SNOWFLAKE_ROLE
  pwd_user VARCHAR DEFAULT 'SNOW_RS_CLI_PASSWORD_TEST';
  pat_name VARCHAR DEFAULT 'SNOW_RS_CLI_TESTS';
  pwd VARCHAR;
  pat VARCHAR;
  other_policies INTEGER;
  rs RESULTSET;
BEGIN
  IF (agent_user LIKE 'EDIT_ME%' OR agent_role LIKE 'EDIT_ME%') THEN
    rs := (SELECT 'ERROR' AS env_var, 'Set agent_user and agent_role at the top of the block, then run again.' AS value);
    RETURN TABLE(rs);
  END IF;

  SELECT COUNT(*) INTO :other_policies
    FROM TABLE(SNOW_RS_CLI_ADMIN.INFORMATION_SCHEMA.POLICY_REFERENCES(
      REF_ENTITY_NAME => UPPER(:agent_user), REF_ENTITY_DOMAIN => 'USER'))
    WHERE POLICY_KIND = 'AUTHENTICATION_POLICY' AND POLICY_NAME <> 'AGENT_PAT_POLICY';
  IF (other_policies > 0) THEN
    rs := (SELECT 'ERROR' AS env_var,
                  'The test user already has another authentication policy; nothing changed. Add NETWORK_POLICY_EVALUATION = ENFORCED_NOT_REQUIRED to its PAT_POLICY instead, remove step 4 from this block, and run again.' AS value);
    RETURN TABLE(rs);
  END IF;

  -- Password user. RANDSTR is alphanumeric; the fixed characters satisfy the default password
  -- policy (upper case, lower case, digit).
  pwd := 'Sr' || RANDSTR(30, RANDOM()) || '7a';
  EXECUTE IMMEDIATE 'CREATE USER IF NOT EXISTS ' || pwd_user ||
    ' TYPE = PERSON DEFAULT_ROLE = PUBLIC COMMENT = ''snowflake-rs-cli: password sign-in tests (ADR 0005)''';
  EXECUTE IMMEDIATE 'ALTER USER ' || pwd_user ||
    ' SET TYPE = PERSON DEFAULT_ROLE = PUBLIC MUST_CHANGE_PASSWORD = FALSE DISABLED = FALSE PASSWORD = ''' || pwd || '''';
  EXECUTE IMMEDIATE 'ALTER USER ' || pwd_user ||
    ' SET AUTHENTICATION POLICY SNOW_RS_CLI_ADMIN.POLICIES.PASSWORD_TEST_POLICY FORCE';

  -- Step 4: PAT policy on the test user (it has no other authentication policy: checked above).
  EXECUTE IMMEDIATE 'ALTER USER "' || UPPER(agent_user) ||
    '" SET AUTHENTICATION POLICY SNOW_RS_CLI_ADMIN.POLICIES.AGENT_PAT_POLICY FORCE';

  -- Step 5: rotate the PAT (remove, then add: the secret is only returned by ADD).
  EXECUTE IMMEDIATE 'ALTER USER "' || UPPER(agent_user) || '" REMOVE PROGRAMMATIC ACCESS TOKEN IF EXISTS ' || pat_name;
  rs := (EXECUTE IMMEDIATE 'ALTER USER "' || UPPER(agent_user) || '" ADD PROGRAMMATIC ACCESS TOKEN ' || pat_name ||
    ' ROLE_RESTRICTION = ''' || UPPER(agent_role) || ''' DAYS_TO_EXPIRY = 365' ||
    ' COMMENT = ''snowflake-rs-cli: PAT sign-in tests (ADR 0005)''');
  LET c CURSOR FOR rs;
  FOR r IN c DO
    pat := r."token_secret";
  END FOR;

  rs := (SELECT 'SNOWFLAKE_TEST_PASSWORD_USER' AS env_var, :pwd_user AS value
         UNION ALL SELECT 'SNOWFLAKE_TEST_PASSWORD', :pwd
         UNION ALL SELECT 'SNOWFLAKE_TEST_PAT', :pat);
  RETURN TABLE(rs);
END;
$$;
