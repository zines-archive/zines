tasm32 /ml /z /kh1000000000 /m9 /q %1
C:\winddk\2600\bin\x86\link iUSER32.lib iKERNEL32.lib /IGNORE:4033 /ENTRY:start /dll /base:0x3a0000 /out:%1.dll /subsystem:windows /def:%1.def %1.obj
pewrite %1.dll
@echo off

