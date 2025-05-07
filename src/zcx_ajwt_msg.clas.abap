CLASS zcx_ajwt_msg DEFINITION
  PUBLIC
  INHERITING FROM cx_static_check
  CREATE PRIVATE.

  PUBLIC SECTION.
    INTERFACES if_t100_dyn_msg.
    INTERFACES if_t100_message.

    CLASS-METHODS raise
      IMPORTING !message TYPE string
      RAISING   zcx_ajwt_msg.

    METHODS constructor
      IMPORTING textid    LIKE if_t100_message=>t100key OPTIONAL
                !previous LIKE previous                 OPTIONAL
                !message  TYPE string                   OPTIONAL.

    METHODS if_message~get_text REDEFINITION.

  PROTECTED SECTION.
    DATA message TYPE string.

  PRIVATE SECTION.
ENDCLASS.


CLASS zcx_ajwt_msg IMPLEMENTATION.
  METHOD constructor ##ADT_SUPPRESS_GENERATION.
    super->constructor( previous = previous ).
    CLEAR me->textid.
    IF textid IS INITIAL.
      if_t100_message~t100key = if_t100_message=>default_textid.
    ELSE.
      if_t100_message~t100key = textid.
    ENDIF.
    me->message = message.
  ENDMETHOD.

  METHOD if_message~get_text.
    result = message.
  ENDMETHOD.

  METHOD raise.
    RAISE EXCEPTION TYPE zcx_ajwt_msg
      EXPORTING
        message = message.
  ENDMETHOD.
ENDCLASS.
