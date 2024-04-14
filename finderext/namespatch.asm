        case on

dummy   private
        end

*
* This is the code that will be patched into the Finder.
* It never actually runs from this location.
*
patchCode start
        jsl >NewCode
        bge *+5
        end

*
* This is the code that is called from the patch.
*
NewCode start
patch1  entry
        ldy |0000                       ; address will be patched in
        cpy #32+1
        bge toolong

patch2  entry
        sty |0000                       ; address will be patched in
        rtl

toolong ldy #33
patch3  entry
        sty |0000                       ; address will be patched in
        dey
        lda #$C900                      ; add '...' as last character
        rtl
        end
