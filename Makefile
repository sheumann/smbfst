CC = occ
CFLAGS = -O-1 -w-1

CRYPTO_SRC = \
           crypto/*.c \
           crypto/*.cc \
           crypto/*.h \
           crypto/*.asm \
           crypto/*.macros \
           crypto/Makefile

HEADERS =  *.h */*.h

FST_OBJ =  fst/smbfst.A \
           smb2/connection.a \
           smb2/session.a \
           smb2/smb2.a \
           smb2/treeconnect.a \
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
           helpers/closerequest.a \
           helpers/createcontext.a \
           helpers/datetime.a \
           helpers/errors.a \
           helpers/filetype.a \
           helpers/path.a \
           helpers/position.a \
           utils/alloc.a \
           utils/charsetutils.a \
           utils/finderstate.a \
           utils/guidutils.a \
           utils/macromantable.a \
           utils/memcasecmp.a \
           utils/random.a \
           utils/readtcp.a

FST_LIBS = crypto/lib65816crypto \
           crypto/lib65816hash

FST_RSRC = fst/smbfst.rez

CDEV_OBJ = cdev/smbcdev.a \
           cdev/addressparser.a \
           cdev/strncasecmp.a \
           cdev/connectsmb.a \
           cdev/loginsmb.a \
           cdev/mountsmbvol.a \
           cdev/charset.a \
           cdev/configfile.a \
           utils/macromantable.a \
           rpc/rpc.a \
           rpc/ndr.a \
           rpc/srvsvc.a \
           mdns/mdnssd.a

CDEV_RSRC = \
           cdev/smbcdev.rez \
           cdev/loginwindow.rez \
           cdev/shareswindow.rez

CDEV_CODE_BINARY = cdev/SMBCDev.bin

MOUNTSMB_OBJ = commands/mountsmb.a

LISTSHARES_OBJ = \
           commands/listshares.a \
           rpc/rpc.a \
           rpc/ndr.a \
           rpc/srvsvc.a

LISTSERVERS_OBJ = \
           commands/listservers.a \
           mdns/mdnssd.a

BINARIES = SMB.FST SMB mountsmb listshares listservers

.PHONY: all
all: $(BINARIES)

%.a: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $<

%.A: %.asm
	$(CC) -c $<

SMB.FST: $(FST_OBJ) $(FST_LIBS) $(FST_RSRC)
	$(CC) $^ -o $@
	iix chtyp -tfst $@

$(CDEV_CODE_BINARY): $(CDEV_OBJ)
	$(CC) -X $^ -o $@

SMB: $(CDEV_RSRC) $(CDEV_CODE_BINARY)
	rm -f $@
	$(CC) -c $< -o $@
	iix chtyp -tcdv $@

mountsmb: $(MOUNTSMB_OBJ)
	$(CC) $^ -o $@

listshares: $(LISTSHARES_OBJ)
	$(CC) $^ -o $@

listservers: $(LISTSERVERS_OBJ)
	$(CC) $^ -o $@

crypto/lib65816crypto crypto/lib65816hash &: $(CRYPTO_SRC)
	cd crypto && make lib65816crypto lib65816hash
	touch crypto/lib65816crypto crypto/lib65816hash

.PHONY: clean
clean:
	cd crypto && make clean
	rm -f */*.a */*.A */*.root */*.ROOT $(BINARIES) $(CDEV_CODE_BINARY)
