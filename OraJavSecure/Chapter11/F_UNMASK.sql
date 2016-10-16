-- Chapter11/F_UNMASK.sql
-- Copyright 2011, David Coffin

CREATE OR REPLACE FUNCTION appsec.f_unmask(
    crypt_raw       RAW,
    m_class_name    v_app_conn_registry.class_name%TYPE,
    m_class_version v_app_conn_registry.class_version%TYPE )
RETURN RAW
AS
    clear_raw RAW(32767) := NULL;
    app_ver   v_application_key.key_version%TYPE := 4;
    app_key   v_application_key.key_bytes%TYPE;
    iv        RAW(16);
BEGIN
    SELECT key_bytes INTO app_key FROM v_application_key WHERE key_version = app_ver;
    app_key := SYS.UTL_RAW.BIT_XOR( app_key,
        SYS.UTL_RAW.CAST_TO_RAW(m_class_version||'SufficientLength') );
    app_key := SYS.DBMS_CRYPTO.HASH( app_key, SYS.DBMS_CRYPTO.HASH_MD5 );
    app_key := SYS.UTL_RAW.CONCAT( app_key, app_key );
    iv := SYS.UTL_RAW.SUBSTR(
        SYS.UTL_RAW.CAST_TO_RAW(m_class_name||'SufficientLength'), 0, 16 );
    clear_raw := SYS.DBMS_CRYPTO.DECRYPT( crypt_raw,
        SYS.DBMS_CRYPTO.ENCRYPT_AES256 + SYS.DBMS_CRYPTO.CHAIN_CBC +
        SYS.DBMS_CRYPTO.PAD_PKCS5, app_key, iv );
    RETURN clear_raw;
END f_unmask;
