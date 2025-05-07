CLASS zcl_ajwt DEFINITION
  PUBLIC FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_jwt_header,
        alg TYPE string, " Algorithm (alg)
        typ TYPE string, " Token type (typ)
      END OF ty_jwt_header.
    TYPES:
      BEGIN OF ty_jwt_payload,
        iss TYPE string, " Issuer (iss)
        sub TYPE string, " Subject (sub)
        aud TYPE string, " Audience (aud)
        exp TYPE string, " Expiration time (exp)
        nbf TYPE string, " Not Before (nbf)
        iat TYPE string, " Issued At (iat)
        jti TYPE string, " JWT ID (jti)
      END OF ty_jwt_payload.

    CONSTANTS:
      BEGIN OF mc_algorithms,
        hs256 TYPE string VALUE 'HS256',
        hs384 TYPE string VALUE 'HS384',
        hs512 TYPE string VALUE 'HS512',
      END OF mc_algorithms.

    CLASS-METHODS generate_token
      IMPORTING is_header       TYPE ty_jwt_header
                is_payload      TYPE ty_jwt_payload
                iv_secret       TYPE string
      RETURNING VALUE(rv_token) TYPE string
      RAISING   zcx_ajwt_msg.

    CLASS-METHODS verify_token
      IMPORTING iv_token        TYPE string
                iv_secret       TYPE string
      RETURNING VALUE(rv_valid) TYPE abap_bool
      RAISING   zcx_ajwt_msg.

    CLASS-METHODS extract_token
      IMPORTING iv_token   TYPE string
      EXPORTING es_header  TYPE ty_jwt_header
                es_payload TYPE ty_jwt_payload
      RAISING   zcx_ajwt_msg.

  PRIVATE SECTION.
    TYPES tt_parts TYPE STANDARD TABLE OF string WITH EMPTY KEY.

    CLASS-METHODS validate_token_parts
      IMPORTING it_parts TYPE STANDARD TABLE
      RAISING   zcx_ajwt_msg.

    CLASS-METHODS json_serialize
      IMPORTING iv_data_object      TYPE any
      RETURNING VALUE(rv_json_data) TYPE string.

    CLASS-METHODS json_deserialize
      IMPORTING iv_json_data          TYPE any
      EXPORTING VALUE(ev_data_object) TYPE any.

    CLASS-METHODS encode_base64url
      IMPORTING iv_input          TYPE string
      RETURNING VALUE(rv_encoded) TYPE string.

    CLASS-METHODS decode_base64url
      IMPORTING iv_input          TYPE string
      RETURNING VALUE(rv_decoded) TYPE string.

    CLASS-METHODS create_signature
      IMPORTING iv_data_to_sign     TYPE string
                iv_secret_key       TYPE string
                iv_hash_algorithm   TYPE string
      RETURNING VALUE(rv_signature) TYPE string
      RAISING   zcx_ajwt_msg.
ENDCLASS.


CLASS zcl_ajwt IMPLEMENTATION.
  METHOD create_signature.
    TRY.
        DATA(lv_hmac_algorithm) = SWITCH string( iv_hash_algorithm
                                                 WHEN mc_algorithms-hs256 THEN 'SHA256'
                                                 WHEN mc_algorithms-hs384 THEN 'SHA384'
                                                 WHEN mc_algorithms-hs512 THEN 'SHA512'
                                                 ELSE                          iv_hash_algorithm ).

        cl_abap_hmac=>calculate_hmac_for_char(
          EXPORTING if_algorithm     = lv_hmac_algorithm
                    if_key           = cl_abap_hmac=>string_to_xstring( iv_secret_key )
                    if_data          = iv_data_to_sign
          IMPORTING ef_hmacb64string = rv_signature ).

        " Make signature URL-safe
        rv_signature = encode_base64url( rv_signature ).
      CATCH cx_abap_message_digest INTO DATA(lx_message).
        zcx_ajwt_msg=>raise( message = lx_message->get_text( ) ).
    ENDTRY.
  ENDMETHOD.

  METHOD decode_base64url.
    rv_decoded = iv_input.

    " First make it standard Base64
    REPLACE ALL OCCURRENCES OF '-' IN rv_decoded WITH '+'.
    REPLACE ALL OCCURRENCES OF '_' IN rv_decoded WITH '/'.

    " Add padding if needed
    DATA(lv_remainder) = strlen( rv_decoded ) MOD 4.
    IF lv_remainder > 0.
      rv_decoded = rv_decoded && repeat( val = '='
                                         occ = 4 - lv_remainder ).
    ENDIF.

    " Then decode
    rv_decoded = cl_http_utility=>decode_base64( rv_decoded ).
  ENDMETHOD.

  METHOD encode_base64url.
    " First encode with standard Base64
    rv_encoded = cl_http_utility=>encode_base64( iv_input ).

    " Then make it URL-safe:
    " 1. Remove line breaks
    REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>cr_lf IN rv_encoded WITH ''.
    REPLACE ALL OCCURRENCES OF cl_abap_char_utilities=>newline IN rv_encoded WITH ''.

    " 2. Replace special characters
    REPLACE ALL OCCURRENCES OF '+' IN rv_encoded WITH '-'.
    REPLACE ALL OCCURRENCES OF '/' IN rv_encoded WITH '_'.

    " 3. Remove padding
    REPLACE ALL OCCURRENCES OF '=' IN rv_encoded WITH ''.
  ENDMETHOD.

  METHOD extract_token.
    DATA lt_parts        TYPE tt_parts.
    DATA lv_header_json  TYPE string.
    DATA lv_payload_json TYPE string.

    " Split token into parts
    SPLIT iv_token AT '.' INTO TABLE lt_parts.

    " Validate token structure
    validate_token_parts( it_parts = lt_parts ).

    " Decode header
    IF es_header IS REQUESTED.
      lv_header_json = decode_base64url( iv_input = lt_parts[ 1 ] ).
      json_deserialize( EXPORTING iv_json_data   = lv_header_json
                        IMPORTING ev_data_object = es_header ).
    ENDIF.

    " Decode payload
    IF es_payload IS REQUESTED.
      lv_payload_json = decode_base64url( iv_input = lt_parts[ 2 ] ).
      json_deserialize( EXPORTING iv_json_data   = lv_payload_json
                        IMPORTING ev_data_object = es_payload ).
    ENDIF.
  ENDMETHOD.

  METHOD generate_token.
    DATA lv_header_json  TYPE string.
    DATA lv_payload_json TYPE string.
    DATA lv_header_b64   TYPE string.
    DATA lv_payload_b64  TYPE string.
    DATA lv_unsigned     TYPE string.
    DATA lv_signature    TYPE string.

    " Serialize header and payload to JSON
    lv_header_json = json_serialize( is_header ).
    lv_payload_json = json_serialize( is_payload ).

    " Base64Url encode header and payload
    lv_header_b64 = encode_base64url( lv_header_json ).
    lv_payload_b64 = encode_base64url( lv_payload_json ).

    " Create unsigned token
    lv_unsigned = |{ lv_header_b64 }.{ lv_payload_b64 }|.

    " Create signature
    lv_signature = create_signature( iv_data_to_sign   = lv_unsigned
                                     iv_secret_key     = iv_secret
                                     iv_hash_algorithm = is_header-alg ).

    " Combine to form final token
    rv_token = |{ lv_unsigned }.{ lv_signature }|.
  ENDMETHOD.

  METHOD json_deserialize.
    /ui2/cl_json=>deserialize( EXPORTING json        = iv_json_data
                                         pretty_name = /ui2/cl_json=>pretty_mode-low_case
                               CHANGING  data        = ev_data_object ).
  ENDMETHOD.

  METHOD json_serialize.
    rv_json_data = /ui2/cl_json=>serialize( data        = iv_data_object
                                            compress    = abap_true
                                            pretty_name = /ui2/cl_json=>pretty_mode-low_case ).
  ENDMETHOD.

  METHOD validate_token_parts.
    IF lines( it_parts ) <> 3.
      zcx_ajwt_msg=>raise( message = 'Invalid JWT token format. Expected 3 parts separated by dots.' ).
    ENDIF.
  ENDMETHOD.

  METHOD verify_token.
    DATA lt_parts      TYPE string_table.
    DATA ls_header     TYPE ty_jwt_header.
    DATA lv_unsigned   TYPE string.
    DATA lv_signature  TYPE string.
    DATA lv_calculated TYPE string.

    " Split token into parts
    SPLIT iv_token AT '.' INTO TABLE lt_parts.

    " Validate token structure
    validate_token_parts( lt_parts ).

    extract_token( EXPORTING iv_token  = iv_token
                   IMPORTING es_header = ls_header ).

    " Reconstruct unsigned part
    lv_unsigned = |{ lt_parts[ 1 ] }.{ lt_parts[ 2 ] }|.
    lv_signature = lt_parts[ 3 ].

    " Calculate expected signature
    TRY.
        lv_calculated = create_signature( iv_data_to_sign   = lv_unsigned
                                          iv_secret_key     = iv_secret
                                          iv_hash_algorithm = ls_header-alg ).
      CATCH zcx_ajwt_msg.
    ENDTRY.

    " Compare signatures
    rv_valid = xsdbool( lv_signature = lv_calculated ).
  ENDMETHOD.
ENDCLASS.
