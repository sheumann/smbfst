#ifndef RPCPDU_H
#define RPCPDU_H

#include <stdint.h>
#include "utils/guid.h"

/*
 * DCE/RPC Protocol Data Unit definitions.
 *
 * See Open Group pub. C706, ch. 12.
 */

typedef GUID uuid_t;

/* common header for connection-oriented RPC PDUs */
typedef struct {
    uint8_t  rpc_vers;
    uint8_t  rpc_vers_minor;
    uint8_t  PTYPE;
    uint8_t  pfc_flags;
    uint8_t  packed_drep[4];
    uint16_t frag_length;
    uint16_t auth_length;
    uint32_t call_id;
} rpc_common_header_t;

/* PTYPE values (for connection-oriented and connectionless PDUs)*/
#define PTYPE_request             0
#define PTYPE_ping                1
#define PTYPE_response            2
#define PTYPE_fault               3
#define PTYPE_working             4
#define PTYPE_nocall              5
#define PTYPE_reject              6
#define PTYPE_ack                 7
#define PTYPE_cl_cancel           8
#define PTYPE_fack                9
#define PTYPE_cancel_ack         10
#define PTYPE_bind               11
#define PTYPE_bind_ack           12
#define PTYPE_bind_nak           13
#define PTYPE_alter_context      14
#define PTYPE_alter_context_resp 15
#define PTYPE_shutdown           17
#define PTYPE_co_cancel          18
#define PTYPE_orphaned           19

/* pfc_flags bits */
#define PFC_FIRST_FRAG      0x01
#define PFC_LAST_FRAG       0x02
#define PFC_PENDING_CANCEL  0x04
#define PFC_RESERVED_1      0x08
#define PFC_CONC_MPX        0x10
#define PFC_DID_NOT_EXECUTE 0x20
#define PFC_MAYBE           0x40
#define PFC_OBJECT_UUID     0x80

/* data representation values */
#define DREP_BIG_ENDIAN    0x00
#define DREP_LITTLE_ENDIAN 0x10
#define DREP_ASCII         0x00
#define DREP_EBCDIC        0x01
#define DREP_IEEE          0
#define DREP_VAX           1
#define DREP_CRAY          2
#define DREP_IBM           3

/* implementations must be able to receive at least this fragment size */
#define MustRecvFragSize 1432

/* major version for connection-oriented RPC */
#define RPC_CO_MAJOR_VERSION 5

typedef uint16_t p_context_id_t;

typedef struct {
    uuid_t   if_uuid;
    uint32_t if_version;
} p_syntax_id_t;

typedef struct {
    p_context_id_t p_cont_id;
    uint8_t        n_transfer_syn;
    uint8_t        reserved;
    p_syntax_id_t  abstract_syntax;
    p_syntax_id_t  transfer_syntax_1;
    /* transfer syntaxes can continue (n_transfer_syn total) */
} p_cont_elem_t;

typedef struct {
    uint8_t       n_context_elem;
    uint8_t       reserved;
    uint16_t      reserved2;
    p_cont_elem_t p_cont_elem_1;
    /* context elements can continue (n_context_elem total) */
} p_cont_list_t;

typedef enum {
    acceptance,
    user_rejection,
    provider_rejection
} p_cont_def_result_t;

typedef enum {
    reason_not_specified,
    abstract_syntax_not_supported,
    proposed_transfer_syntaxes_not_supported,
    local_limit_exceeded
} p_provider_reason_t;

typedef struct {
    p_cont_def_result_t result;
    p_provider_reason_t reason;
    p_syntax_id_t       transfer_syntax;
} p_result_t;

typedef struct {
    uint8_t    n_results;
    uint8_t    reserved;
    uint16_t   reserved2;
    p_result_t p_results[/*n_results*/];
} p_result_list_t;

typedef struct {
    uint8_t major;
    uint8_t minor;
} version_t;

typedef version_t p_rt_version_t;

typedef struct {
    uint8_t n_protocols;
    p_rt_version_t p_protocols[/*n_protocols*/];
} p_rt_versions_supported_t;

typedef struct {
    uint16_t length;
    char     port_spec[/*length*/];
} port_any_t;

typedef uint16_t p_reject_reason_t;

/* rejections reasons used in bind_nak */
#define REASON_NOT_SPECIFIED            0
#define TEMPORARY_CONGESTION            1
#define LOCAL_LIMIT_EXCEEDED            2
#define CALLED_PADDR_UNKNOWN            3
#define PROTOCOL_VERSION_NOT_SUPPORTED  4
#define DEFAULT_CONTEXT_NOT_SUPPORTED   5
#define USER_DATA_NOT_READABLE          6
#define NO_PSAP_AVAILABLE               7

/* bind PDU */
typedef struct {
    rpc_common_header_t hdr;
    uint16_t            max_xmit_frag;
    uint16_t            max_recv_frag;
    uint32_t            assoc_group_id;
    p_cont_list_t       p_context_elem;
    /* remaining member is optional and at a variable offset */
//  auth_verifier_co_t  auth_verifier;
} rpcconn_bind_hdr_t;

/* bind_ack PDU */
typedef struct {
    rpc_common_header_t hdr;
    uint16_t            max_xmit_frag;
    uint16_t            max_recv_frag;
    uint32_t            assoc_group_id;
    /* remaining members have flexible fields or are at variable offsets */
//  port_any_t          sec_addr;
//  uint8_t             pad2[]; // to restore 4-byte alignment    
//  p_result_list_t     p_result_list;
//  auth_verifier_co_t  auth_verifier;
} rpcconn_bind_ack_hdr_t;

/* bind_nak PDU */
typedef struct {
    rpc_common_header_t hdr;
    p_reject_reason_t   provider_reject_reason;
    /* remaining member has a flexible field */
//  p_rt_versions_supported_t versions;
} rpcconn_bind_nak_hdr_t;

/* request PDU */
typedef struct {
    rpc_common_header_t hdr;
    uint32_t            alloc_hint;
    p_context_id_t      p_cont_id;
    uint16_t            opnum;
    /* remaining members are optional and/or at variable offsets */
//  uuid_t              object;
    uint8_t             stub_data[];
//  auth_verifier_co_t  auth_verifier;
} rpcconn_request_hdr_t;

/* response PDU */
typedef struct {
    rpc_common_header_t hdr;
    uint32_t            alloc_hint;
    p_context_id_t      p_cont_id;
    uint8_t             cancel_count;
    uint8_t             reserved;
    uint8_t             stub_data[];
    /* remaining member is optional and at a variable offset */
//  auth_verifier_co_t  auth_verifier;
} rpcconn_response_hdr_t;

#endif
