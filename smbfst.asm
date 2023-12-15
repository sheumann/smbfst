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

sys_entry start
        lda     #0
        clc
        rtl
        end

app_entry start
        lda     #badSystemCall
        sec
        rtl
        end
