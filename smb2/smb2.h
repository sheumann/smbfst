#ifndef SMB2_H
#define SMB2_H

#include <stdint.h>
#include <stddef.h>
#include <uchar.h>

#include "smb2/smb2proto.h"
#include "smb2/connection.h"
#include "smb2/session.h"
#include "utils/readtcp.h"
#include "driver/driver.h"

#define msgBodyHeader          (*(SMB2_Common_Header*)msg.body)
#define negotiateRequest       (*(SMB2_NEGOTIATE_Request*)msg.body)
#define negotiateResponse      (*(SMB2_NEGOTIATE_Response*)msg.body)
#define sessionSetupRequest    (*(SMB2_SESSION_SETUP_Request*)msg.body)
#define sessionSetupResponse   (*(SMB2_SESSION_SETUP_Response*)msg.body)
#define logoffRequest          (*(SMB2_LOGOFF_Request*)msg.body)
#define logoffResponse         (*(SMB2_LOGOFF_Response*)msg.body)
#define treeConnectRequest     (*(SMB2_TREE_CONNECT_Request*)msg.body)
#define treeConnectResponse    (*(SMB2_TREE_CONNECT_Response*)msg.body)
#define treeDisconnectRequest  (*(SMB2_TREE_DISCONNECT_Request*)msg.body)
#define treeDisconnectResponse (*(SMB2_TREE_DISCONNECT_Response*)msg.body)
#define createRequest          (*(SMB2_CREATE_Request*)msg.body)
#define createResponse         (*(SMB2_CREATE_Response*)msg.body)
#define readRequest            (*(SMB2_READ_Request*)msg.body)
#define readResponse           (*(SMB2_READ_Response*)msg.body)
#define closeRequest           (*(SMB2_CLOSE_Request*)msg.body)
#define closeResponse          (*(SMB2_CLOSE_Response*)msg.body)
#define queryDirectoryRequest  (*(SMB2_QUERY_DIRECTORY_Request*)msg.body)
#define queryDirectoryResponse (*(SMB2_QUERY_DIRECTORY_Response*)msg.body)
#define queryInfoRequest       (*(SMB2_QUERY_INFO_Request*)msg.body)
#define queryInfoResponse      (*(SMB2_QUERY_INFO_Response*)msg.body)
#define setInfoRequest         (*(SMB2_SET_INFO_Request*)msg.body)
#define setInfoResponse        (*(SMB2_SET_INFO_Response*)msg.body)
#define flushRequest           (*(SMB2_FLUSH_Request*)msg.body)
#define flushResponse          (*(SMB2_FLUSH_Response*)msg.body)
#define writeRequest           (*(SMB2_WRITE_Request*)msg.body)
#define writeResponse          (*(SMB2_WRITE_Response*)msg.body)

/*
 * Verify that a offset/length pair specifying a buffer within the last
 * message received actually refer to locations within that message.
 *
 * Note: argument values should be in range of uint16_t, not 32-bit or larger.
 */
#define VerifyBuffer(offset,length) \
    ((uint32_t)(offset) + (length) <= bodySize + sizeof(SMB2Header))

// max read/write size that MsgRec is sized to support
#define IO_BUFFER_SIZE 32768u

// Size of body part of MsgRec.
// This is sized to accommodate the largest message we support, which is
// a READ response with IO_BUFFER_SIZE bytes starting at offset 255.
#define BODY_SIZE (255 - sizeof(SMB2Header) + IO_BUFFER_SIZE)

typedef struct {
    DirectTCPHeader directTCPHeader;
    SMB2Header smb2Header;
    unsigned char body[BODY_SIZE];
} MsgRec;

extern MsgRec msg;

extern uint16_t bodySize;   // size of last message received

typedef struct {
    DIB *dib;
    SMB2_FILEID *fileId;
} ReconnectInfo;

extern ReconnectInfo reconnectInfo;

ReadStatus SendRequestAndGetResponse(DIB *dib, uint16_t command,
                                     uint16_t bodyLength);
void InitSMB(void);

#endif
