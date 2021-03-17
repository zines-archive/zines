C:\tasm32\bin\tasm32 /ml /z /m9 /q %1
C:\winddk\2600\bin\x86\link  iNTOSKRNL.lib /IGNORE:4033 /ENTRY:start /nologo /driver /base:0x10000 /align:32 /out:%1.sys /subsystem:native %1.obj /SECTION:.text,RWEX 
@echo off
del %1.obj