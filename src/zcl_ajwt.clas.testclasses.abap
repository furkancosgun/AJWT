CLASS ltcl_ajwt DEFINITION FINAL
  FOR TESTING RISK LEVEL HARMLESS DURATION SHORT.

  PRIVATE SECTION.
    METHODS test_valid_token       FOR TESTING.
    METHODS test_invalid_secret    FOR TESTING.
    METHODS test_different_payload FOR TESTING.
    METHODS test_missing_fields    FOR TESTING.
    METHODS test_corrupted_token   FOR TESTING.
ENDCLASS.


CLASS ltcl_ajwt IMPLEMENTATION.
  METHOD test_valid_token.
    DATA(lv_token) = zcl_ajwt=>generate_token( is_header  = VALUE #( alg = zcl_ajwt=>mc_algorithms-hs256
                                                                     typ = 'JWT' )
                                               is_payload = VALUE #( sub = 'user123' )
                                               iv_secret  = 'secret123' ).

    cl_abap_unit_assert=>assert_true( zcl_ajwt=>verify_token( iv_token  = lv_token
                                                              iv_secret = 'secret123' ) ).

    zcl_ajwt=>extract_token( EXPORTING iv_token   = lv_token
                             IMPORTING es_payload = DATA(ls_payload) ).

    cl_abap_unit_assert=>assert_equals( exp = 'user123'
                                        act = ls_payload-sub ).
  ENDMETHOD.

  METHOD test_invalid_secret.
    DATA(lv_token) = zcl_ajwt=>generate_token( is_header  = VALUE #( alg = 'HS256'
                                                                     typ = 'JWT' )
                                               is_payload = VALUE #( sub = 'userX' )
                                               iv_secret  = 'correct_secret' ).

    cl_abap_unit_assert=>assert_false( zcl_ajwt=>verify_token( iv_token  = lv_token
                                                               iv_secret = 'wrong_secret' ) ).
  ENDMETHOD.

  METHOD test_different_payload.
    DATA(lv_token) = zcl_ajwt=>generate_token( is_header  = VALUE #( alg = 'HS256'
                                                                     typ = 'JWT' )
                                               is_payload = VALUE #( iss = 'issuer_system'
                                                                     sub = 'test_user'
                                                                     aud = 'target_audience'
                                                                     iat = '1715085600'  " example timestamp
                                                                     jti = 'jwt-001' )
                                               iv_secret  = 's3cr3t!' ).

    cl_abap_unit_assert=>assert_true( zcl_ajwt=>verify_token( iv_token  = lv_token
                                                              iv_secret = 's3cr3t!' ) ).

    zcl_ajwt=>extract_token( EXPORTING iv_token   = lv_token
                             IMPORTING es_payload = DATA(ls_payload) ).

    cl_abap_unit_assert=>assert_equals( exp = 'issuer_system'
                                        act = ls_payload-iss ).
    cl_abap_unit_assert=>assert_equals( exp = 'test_user'
                                        act = ls_payload-sub ).
    cl_abap_unit_assert=>assert_equals( exp = 'target_audience'
                                        act = ls_payload-aud ).
    cl_abap_unit_assert=>assert_equals( exp = '1715085600'
                                        act = ls_payload-iat ).
    cl_abap_unit_assert=>assert_equals( exp = 'jwt-001'
                                        act = ls_payload-jti ).
  ENDMETHOD.

  METHOD test_missing_fields.
    DATA(lv_token) = zcl_ajwt=>generate_token( is_header  = VALUE #( alg = 'HS256'
                                                                     typ = 'JWT' )
                                               is_payload = VALUE #( )
                                               iv_secret  = 'minimal' ).

    cl_abap_unit_assert=>assert_true( zcl_ajwt=>verify_token( iv_token  = lv_token
                                                              iv_secret = 'minimal' ) ).

    zcl_ajwt=>extract_token( EXPORTING iv_token   = lv_token
                             IMPORTING es_payload = DATA(ls_payload) ).

    cl_abap_unit_assert=>assert_initial( ls_payload-sub ).
    cl_abap_unit_assert=>assert_initial( ls_payload-iss ).
    cl_abap_unit_assert=>assert_initial( ls_payload-aud ).
    cl_abap_unit_assert=>assert_initial( ls_payload-exp ).
    cl_abap_unit_assert=>assert_initial( ls_payload-nbf ).
    cl_abap_unit_assert=>assert_initial( ls_payload-iat ).
    cl_abap_unit_assert=>assert_initial( ls_payload-jti ).
  ENDMETHOD.

  METHOD test_corrupted_token.

    DATA(lv_token) = zcl_ajwt=>generate_token( is_header  = VALUE #( alg = 'HS256'
                                                                     typ = 'JWT' )
                                               is_payload = VALUE #( sub = 'corrupt' )
                                               iv_secret  = 'topsecret' ).

    lv_token = |{ lv_token }A|.

    cl_abap_unit_assert=>assert_false( zcl_ajwt=>verify_token( iv_token  = lv_token
                                                               iv_secret = 'topsecret' ) ).
    lv_token = substring( val = lv_token
                          len = strlen( lv_token ) - 1 ).

    cl_abap_unit_assert=>assert_true( zcl_ajwt=>verify_token( iv_token  = lv_token
                                                              iv_secret = 'topsecret' ) ).
  ENDMETHOD.
ENDCLASS.
