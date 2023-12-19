        case    on

        copy    13/AInclude/E16.GSOS

; ID for SMB FST
SMB_FST_ID gequ $800e

fstheader start
        dc      c'FST '                 ; signature
        dc      a4'app_entry'           ; application entry point
        dc      a4'sys_entry'           ; system entry point
        dc      i2'SMB_FST_ID'          ; FST ID
        dc      i2'$0002'               ; attributes: non-apple format
        dc      i2'$8001'               ; version 0.1 (prototype)
        dc      i2'512'                 ; block size
        dc      i4'$ffffffff'           ; max volume size in blocks
        dc      i4'1'                   ; min volume size in blocks
        dc      i4'$ffffffff'           ; max file size in bytes
        dc      i4'0'                   ; reserved
        dc      i1'3',c'SMB'            ; FST name (p-string)
;                                       ; FST info string (shown in text boot)
        dc      i1'7',c'SMB FST               v00.01 prototype'
        dc      i2'0'
;                                       ; credits for FST
        dc      i1'26',c'SMB FST by Stephen Heumann'
        end

*
* Entry point for system calls from GS/OS
*
* On entry, X = call number * 2.
*
* Return with carry set on error.
*
sys_entry start
max_sys_call equ 4

        phk                             ; set databank (no need to save/restore)
        plb
        
        cpx     #max_sys_call*2+1       ; check for invalid call
        bge     invalid

        txa                             ; get address to call
        asl     a
        tax
        lda     sys_calls-4+1,x
        sta     thecall+2
        lda     sys_calls-4,x
        sta     thecall+1
        
thecall jsl     >000000                 ; modified above

        cmp     #1                      ; set/clear carry as appropriate
        rtl

invalid lda     #badSystemCall
        sec
        rtl

sys_calls anop                          ; table of system calls
        dc      a4'Startup'
        dc      a4'Shutdown'
        dc      a4'SysRemoveVol'
        dc      a4'DeferredFlush'
        end


*
* Entry point for GS/OS calls originating from applications
*
* x = call number (lower byte) * 2
* y = class * 2 (i.e. 0 for P16, or 2 for GS/OS)
*
* On exit, c indicates an error and a = error number
*
app_entry start
maxRegularCall equ $25                  ; max call we handle, except FSTSpecific
FSTSpecificCall equ $33                 ; FSTSpecific call number (low byte)
pblock  equ     $32                     ; pblock ptr (on GS/OS direct page)
SYS_EXIT equ    $01fc40                 ; SYS_EXIT system service call
        
        phk                             ; set databank (no need to save/restore)
        plb

        txa
        asl     a
        tax
        
        cpx     #maxRegularCall*4+1     ; check that call number is in range
        blt     check2
        cpx     #FSTSpecificCall*4
        beq     fstspec
        bra     badcall

        lda     gsos_calls-4+2,x        ; get address to call
        sta     thecall+2
        lda     gsos_calls-4+1,x
        sta     thecall+1
        
check2  lda     gsos_calls-1,x          ; get max pcount
        and     #$00FF
        beq     badcall                 ; check for invalid call

        tyx                             ; if class 1 ...
        beq     push_params
        
        cmp     [pblock]                ;   check against max pcount
        blt     bad_pcount
        
        lda     [pblock]                ;   get pcount to pass to call
        tay

push_params anop
        pea     0                       ; push GS/OS direct page pointer
        phd
        phy                             ; push pcount (or 0 for class 0)
        pei     pblock+2                ; push pblock pointer
        pei     pblock

thecall jsl     >000000                 ; modified above

return  cmp     #1                      ; set/clear carry based on result
        jml     >SYS_EXIT               ; return via SYS_EXIT

bad_pcount anop                         ; indicate bad parameter count
        lda     #invalidPcount
        bra     return

badcall lda     #badSystemCall          ; indicate bad system call
        bra     return

; Handle FSTSpecific subcalls
fstspec tyx                             ; must be class 1
        beq     badcall

        lda     [pblock]                ; must have at least 2 params
        cmp     #2
        blt     bad_pcount
        
        ldy     #4                      ; get command number
        lda     [pblock],y
        
        cmp     #maxFSTSpecificCall+1   ; check for valid call number
        bge     badcall
        
        asl     a
        asl     a
        tax

        lda     fstspecific_calls+1,x   ; get address to call
        sta     thecall+2
        lda     fstspecific_calls,x
        sta     thecall+1
        
        lda     [pblock]                ; get pcount
        tay
        bra     push_params             ; do the call

; Table of GS/OS calls handled here: max pCount, followed by handler func
;
; ^ = new or updated in System 6
; Everything except JudgeName also has a class 0 version.
gsos_calls anop
        dc      i1'7',a3'Create'        ; $2001 Create
        dc      i1'1',a3'Destroy'       ; $2002 Destroy
        dc      i4'0'
        dc      i1'3',a3'ChangePath'    ; $2004 ChangePath ^
        dc      i1'12',a3'SetFileInfo'  ; $2005 SetFilelnfo
        dc      i1'12',a3'GetFileInfo'  ; $2006 GetFilelnfo
        dc      i1'6',a3'JudgeName'     ; $2007 JudgeName ^
        dc      i1'8',a3'Volume'        ; $2008 Volume ^
        dc      i4'0'
        dc      i4'0'
        dc      i1'1',a3'ClearBackupBit' ;$200B ClearBackupBit
        dc      i4'0'
        dc      i4'0'
        dc      i4'0'
        dc      i4'0'
        dc      i1'15',a3'Open'         ; $2010 Open
        dc      i4'0'
        dc      i1'5',a3'Read'          ; $2012 Read
        dc      i1'5',a3'Write'         ; $2013 Write
        dc      i1'1',a3'Close'         ; $2014 Close
        dc      i1'1',a3'Flush'         ; $2015 Flush
        dc      i1'3',a3'SetMark'       ; $2016 SetMark
        dc      i1'2',a3'GetMark'       ; $2017 GetMark
        dc      i1'3',a3'SetEOF'        ; $2018 SetEOF
        dc      i1'2',a3'GetEOF'        ; $2019 GetEOF
        dc      i4'0'
        dc      i4'0'
        dc      i1'17',a3'GetDirEntry'  ; $201C GetDirEntry
        dc      i4'0'
        dc      i4'0'
        dc      i4'0'
        dc      i1'2',a3'GetDevNumber'  ; $2020 GetDevNumber
        dc      i4'0'
        dc      i4'0'
        dc      i4'0'
        dc      i1'6',a3'Format'        ; $2024 Format ^
        dc      i1'6',a3'EraseDisk'     ; $2025 EraseDisk ^

; Table of FSTSpecific subcalls
fstspecific_calls anop
        dc      i4'SMB_Connect'
        dc      i4'SMB_Connection_Retain'
        dc      i4'SMB_Connection_Release'
        dc      i4'SMB_Authenticate'
        dc      i4'SMB_Session_Retain'
        dc      i4'SMB_Session_Release'
        dc      i4'SMB_Mount'
fstspecific_end anop

maxFSTSpecificCall equ -1+(fstspecific_end-fstspecific_calls)/4
        end
