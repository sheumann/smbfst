void Negotiate(Connection *connection);
void SessionSetup(Connection *connection);
uint32_t TreeConnect(Connection *connection, char16_t share[],
    uint16_t shareSize);
void Open(Connection *connection, uint32_t treeId,
    char16_t file[], uint16_t fileSize);
    