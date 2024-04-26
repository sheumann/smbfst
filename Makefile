CC = occ
CFLAGS = -O-1 -w-1

HEADERS =  defs.h \
           auth/auth.h \
           auth/ntlm.h \
           auth/ntlmproto.h \
           crypto/aes.h \
           crypto/md4.h \
           crypto/md5.h \
           crypto/rc4.h \
           crypto/sha1.h \
           crypto/sha256.h \
           driver/driver.h \
           fst/fstspecific.h \
           fstops/GetFileInfo.h \
           gsos/gsosdata.h \
           gsos/gsosutils.h \
           helpers/afpinfo.h \
           helpers/attributes.h \
           helpers/blocks.h \
           helpers/createcontext.h \
           helpers/datetime.h \
           helpers/errors.h \
           helpers/filetype.h \
           helpers/path.h \
           helpers/position.h \
           rpc/ndr.h \
           rpc/rpc.h \
           rpc/rpcpdu.h \
           rpc/srvsvc.h \
           rpc/srvsvcproto.h \
           smb2/aapl.h \
           smb2/connection.h \
           smb2/fileinfo.h \
           smb2/ntstatus.h \
           smb2/session.h \
           smb2/smb2.h \
           smb2/smb2proto.h \
           systemops/Startup.h \
           utils/alloc.h \
           utils/endian.h \
           utils/guid.h \
           utils/macromantable.h \
           utils/random.h \
           utils/readtcp.h

FST_OBJ =  fst/smbfst.A \
           smb2/connection.a \
           smb2/session.a \
           smb2/smb2.a \
           systemops/DeferredFlush.a \
           systemops/Shutdown.a \
           systemops/Startup.a \
           systemops/SysRemoveVol.a \
           fstops/ChangePath.a \
           fstops/ClearBackupBit.a \
           fstops/Close.a \
           fstops/Create.a \
           fstops/Destroy.a \
           fstops/EraseDisk.a \
           fstops/Flush.a \
           fstops/Format.a \
           fstops/GetDevNumber.a \
           fstops/GetDirEntry.a \
           fstops/GetEOF.a \
           fstops/GetFileInfo.a \
           fstops/GetMark.a \
           fstops/JudgeName.a \
           fstops/Open.a \
           fstops/Read.a \
           fstops/SetEOF.a \
           fstops/SetFileInfo.a \
           fstops/SetMark.a \
           fstops/Volume.a \
           fstops/Write.a \
           smbops/Authenticate.a \
           smbops/Connect.a \
           smbops/Connection_Release.a \
           smbops/Connection_Retain.a \
           smbops/Mount.a \
           smbops/Session_Release.a \
           smbops/Session_Retain.a \
           auth/auth.a \
           auth/ntlm.a \
           gsos/gsosdata.a \
           gsos/gsosutils.a \
           driver/driver.a \
           helpers/afpinfo.a \
           helpers/attributes.a \
           helpers/blocks.a \
           helpers/createcontext.a \
           helpers/datetime.a \
           helpers/errors.a \
           helpers/filetype.a \
           helpers/path.a \
           helpers/position.a \
           utils/alloc.a \
           utils/macromantable.a \
           utils/random.a \
           utils/readtcp.a

FST_LIBS = crypto/lib65816crypto \
           crypto/lib65816hash

FEXT_OBJ = finderext/longnames.a \
           finderext/namespatch.A

CDEV_HEADERS = \
           cdev/addressparser.h \
           cdev/charset.h \
           cdev/connectsmb.h \
           cdev/errorcodes.h \
           cdev/loginsmb.h \
           cdev/mountsmbvol.h \
           cdev/strncasecmp.h

CDEV_OBJ = cdev/smbcdev.a \
           cdev/addressparser.a \
           cdev/strncasecmp.a \
           cdev/connectsmb.a \
           cdev/loginsmb.a \
           cdev/mountsmbvol.a \
           cdev/charset.a \
           utils/macromantable.a

CDEV_RSRC = cdev/smbcdev.rez

CDEV_CODE_BINARY = cdev/SMBMounter.obj

MOUNTSMB_OBJ = commands/mountsmb.a

LISTSHARES_OBJ = \
           commands/listshares.a \
           rpc/rpc.a \
           rpc/ndr.a \
           rpc/srvsvc.a

BINARIES = SMB.FST LongNamesPatch SMBMounter mountsmb listshares

.PHONY: all
all: $(BINARIES)

%.a: %.c $(HEADERS) $(CDEV_HEADERS)
	$(CC) $(CFLAGS) -c $<

%.A: %.asm
	$(CC) -c $<

SMB.FST: $(FST_OBJ) $(FST_LIBS)
	$(CC) $^ -o $@
	iix chtyp -tfst $@

LongNamesPatch: $(FEXT_OBJ)
	$(CC) $^ -o $@
	iix chtyp -t 0xBC -a 0x0001 LongNamesPatch

$(CDEV_CODE_BINARY): $(CDEV_OBJ)
	$(CC) -X $^ -o $@

SMBMounter: $(CDEV_RSRC) $(CDEV_CODE_BINARY)
	$(CC) -c $< -o $@
	iix chtyp -tcdv $@

mountsmb: $(MOUNTSMB_OBJ)
	$(CC) $^ -o $@

listshares: $(LISTSHARES_OBJ)
	$(CC) $^ -o $@

crypto/lib65816crypto crypto/lib65816hash &: crypto/*.* crypto/Makefile
	cd crypto && make lib65816crypto lib65816hash
	touch crypto/lib65816crypto crypto/lib65816hash

.PHONY: clean
clean:
	cd crypto && make clean
	rm -f */*.a */*.A */*.root */*.ROOT $(BINARIES) $(CDEV_CODE_BINARY)
