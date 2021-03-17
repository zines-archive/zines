#include        <stdio.h>
#include        <windows.h>
#include        "pe.h"


int main(int argc, char **argv){
        DWORD   temp, dllbase, *apiptr;
        FILE    *dllfile, *deffile, *extrnfile;
        peheader_struct *pe;
        IMAGE_EXPORT_DIRECTORY *export_table;
        BYTE *api_name, dll_src[1024]={0}, dll_def[1024]={0}, dll_inc[1024]={0};
        
        if      (argc == 2){
                printf("[X] Usage dllcreatetor <dll_name> <wanted_output>\n");
                return 1;
        }
        
        strcpy(dll_src, argv[2]);
        strcat(dll_src, ".asm");
        strcpy(dll_def, argv[2]);
        strcat(dll_def, ".def");
        strcpy(dll_inc, argv[2]);
        strcat(dll_inc, ".inc");
        
        dllbase = (DWORD) LoadLibrary(argv[1]);
        if      (dllbase == 0){
                printf("[X] Cann't find %s dll\n", argv[1]);
                return 1;
        }else
                printf("[*] dll %s loaded at 0x%.08X\n",argv[1], dllbase);
        
        __asm{
                mov     eax, dllbase
                add     eax, [eax+3ch]
                mov     pe, eax
        }
        
        temp =  pe->pe_export;
        temp+=dllbase;
        export_table = (IMAGE_EXPORT_DIRECTORY *)temp;
        
        //make dll sources
        dllfile = fopen(dll_src, "w");
        deffile = fopen(dll_def, "w");
        extrnfile = fopen(dll_inc, "w");
        
        fprintf(deffile, "EXPORTS\n");
        apiptr =(DWORD *)( dllbase + export_table->AddressOfNames);
        for (DWORD i = 0; i<export_table->NumberOfNames; i++){
                temp = (DWORD)apiptr[i] + dllbase;
                api_name = (char *)temp;        
                fprintf(deffile,"%s=my_%s\n", api_name, api_name);      //store dll name in .def file
                fprintf(extrnfile, "extrn                   C       _imp__%s:dword\n", api_name);
                fprintf(extrnfile, "%s  equ     _imp__%s\n", api_name, api_name);
                fprintf(dllfile, "public my_%s\n", api_name);
                fprintf(dllfile, "my_%s:\n", api_name);
                fprintf(dllfile, "                        jmp     %s\n", api_name);
                fprintf(dllfile, "                        retn\n\n\n");
        }      
        
        printf("[*] %s dll source created\n", dll_src);
        printf("[*] %s dll def created\n", dll_def);
        printf("[*] %s dll extern created\n", dll_inc);
        
}
        
        
