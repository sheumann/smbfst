void Negotiate(Connection *connection);
void SessionSetup(Connection *connection);
uint32_t TreeConnect(Connection *connection, char16_t share[],
    uint16_t shareSize);
SMB2_FILEID Open(Connection *connection, uint32_t treeId,
    char16_t file[], uint16_t fileSize);
uint32_t Read(Connection *connection, uint32_t treeId, SMB2_FILEID file,
    uint64_t offset, uint16_t length, void *buf);
void Close(Connection *connection, uint32_t treeId, SMB2_FILEID file);
uint16_t QueryDirectory(Connection *connection, uint32_t treeId,
    SMB2_FILEID file, uint16_t length, void *buf);
