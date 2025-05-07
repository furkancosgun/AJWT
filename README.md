# AJWT

This repository contains an ABAP class `zcl_ajwt` that provides functionality for generating, verifying, and extracting information from JSON Web Tokens (JWTs). It supports HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 signing algorithms.

---

## Key Features

- **JWT Generation:** Creates JWTs with customizable headers and payloads.
- **JWT Verification:** Verifies the signature of a given JWT using a secret key.
- **JWT Extraction:** Extracts the header and payload from a JWT.
- **Algorithm Support:** Supports HS256, HS384, and HS512 HMAC signing algorithms.
- **Base64Url Encoding/Decoding:** Handles the Base64Url encoding and decoding required for JWTs.
- **JSON Handling:** Utilizes standard ABAP JSON serialization and deserialization functionalities.
- **Unit Tests:** Includes comprehensive unit tests to ensure the reliability of the class.

---

## Installation

To use the `zcl_ajwt` class in your ABAP project:

1.  **Create the class:** Use transaction `SE24` to create a new class named `zcl_ajwt`.
2.  **Copy the code:** Copy the ABAP code provided above into the corresponding sections of the class definition and implementation.
3.  **Create the exception class:** Use transaction `SE24` to create a new exception class named `zcx_ajwt_msg` with a text element for messages.
4.  **Activate the class and exception:** Activate both the `zcl_ajwt` class and the `zcx_ajwt_msg` exception class.

---

## Usage

Here are some examples of how to use the `zcl_ajwt` class:

### Generating a JWT

```abap
    TRY.
        DATA(ls_header) = VALUE zcl_ajwt=>ty_jwt_header( alg = zcl_ajwt=>mc_algorithms-hs256
                                                         typ = 'JWT' ).
        DATA(ls_payload) = VALUE zcl_ajwt=>ty_jwt_payload( sub = 'user123'
                                                           iss = 'my-app' ).
        DATA(lv_secret) = |your-secret-key|.

        DATA(lv_jwt_token) = zcl_ajwt=>generate_token( is_header  = ls_header
                                                       is_payload = ls_payload
                                                       iv_secret  = lv_secret ).

        WRITE: / 'Generated JWT:', lv_jwt_token.

      CATCH zcx_ajwt_msg INTO DATA(lx_jwt_exception).
        WRITE: / 'Error generating JWT:', lx_jwt_exception->get_text( ).
    ENDTRY.
```

### Verifying a JWT

```abap
    DATA(lv_token_to_verify) = |eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoibXktYXBwIiwiZXhwIjoiMTcwMDAwMDAwMCJ9.example_signature|. 
    DATA(lv_verification_secret) = |your-secret-key|.

    TRY.
        DATA(lv_is_valid) = zcl_ajwt=>verify_token( iv_token  = lv_token_to_verify
                                                    iv_secret = lv_verification_secret ).

        IF lv_is_valid = abap_true.
          WRITE / 'JWT is valid.'.
        ELSE.
          WRITE / 'JWT is invalid.'.
        ENDIF.

      CATCH zcx_ajwt_msg INTO DATA(lx_jwt_exception).
        WRITE: / 'Error verifying JWT:', lx_jwt_exception->get_text( ).
    ENDTRY.
```

### Extracting Header and Payload from a JWT

```abap
    DATA(lv_token_to_extract) = |eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoibXktYXBwIiwiZXhwIjoiMTcwMDAwMDAwMCJ9.example_signature|.

    TRY.
        zcl_ajwt=>extract_token( EXPORTING iv_token   = lv_token_to_extract
                                 IMPORTING es_header  = ls_extracted_header
                                           es_payload = ls_extracted_payload ).

        WRITE / 'Extracted Header:'.
        WRITE: / '  Algorithm:', ls_extracted_header-alg.
        WRITE: / '  Type:', ls_extracted_header-typ.

        WRITE / 'Extracted Payload:'.
        WRITE: / '  Subject:', ls_extracted_payload-sub.
        WRITE: / '  Issuer:', ls_extracted_payload-iss.
        WRITE: / '  Expiration:', ls_extracted_payload-exp.

      CATCH zcx_ajwt_msg INTO DATA(lx_jwt_exception).
        WRITE: / 'Error extracting JWT:', lx_jwt_exception->get_text( ).
    ENDTRY.
```

---

## Unit Tests

The repository includes a local test class `ltcl_ajwt` to verify the functionality of the `zcl_ajwt` class. You can run these tests using the ABAP Unit Test Cockpit.

The test class covers the following scenarios:

- Generating and verifying a valid token.
- Verifying a token with an invalid secret.
- Verifying a token with a different payload.
- Generating and verifying a token with missing payload fields.
- Testing the verification of a corrupted token.

---

## Contributing

Contributions to this project are welcome. Feel free to open issues or submit pull requests with improvements or bug fixes.

---

## License

This project is licensed under the [MIT License](LICENSE).
