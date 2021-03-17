/**********************************************************************
 * MineSweeper.cpp - trew@exploit.us
 *
 * This is supplemental code intended to accompany 'Introduction to
 * Reverse Engineering Windows Applications' as part of the Uninformed
 * Journal.  This application reveals and/or removes mines from the
 * WinMine grid.  Note, this code only works on the version of WinMine
 * shipped with WinXP, as the versions differ between releases of
 * Windows.
 *
 *********************************************************************/

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

#define BOMB_HIDDEN         0x8f
#define BOMB_REVEALED       0x8a
#define BLANK               0x0f
#define GRID_ADDRESS        0x1005360
#define GRID_SIZE           0x300

int main(int argc, char *argv[]) {

    HANDLE    hProcessSnap        = NULL;
    HANDLE    hWinMineProc        = NULL;
        
    PROCESSENTRY32 peProcess      = {0};

    unsigned char procFound       = 0;
    unsigned long bytesWritten    = 0;
    unsigned char *grid           = 0;
    unsigned char replacement     = BOMB_REVEALED;
    unsigned int x    i           = 0;

    grid = (unsigned char *)malloc(GRID_SIZE);

    if(!grid)
        return 0;

    if(argc > 1) {
        if(stricmp(argv[1], "remove") == 0) {
            replacement = BLANK;
        }
    }

    //Get a list of running processes
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
    //Ensure the handle is valid
    if(hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("Unable to get process list (%d).\n", GetLastError());
        return 0;
    }
                
    peProcess.dwSize = sizeof(PROCESSENTRY32);

    //Get first process in list
    if(Process32First(hProcessSnap, &peProcess)) {

        do {
            //Is it's winmine.exe?
            if(!stricmp(peProcess.szExeFile, "winmine.exe")) {

                printf("Found WinMine Process ID (%d)\n", peProcess.th32ProcessID);
                procFound = 1;

                //Get handle on winmine process
                hWinMineProc = OpenProcess(PROCESS_ALL_ACCESS, 
                                           1, 
                                           peProcess.th32ProcessID);
                        
                //Make sure the handle is valid
                if(hWinMineProc == NULL) {
                    printf("Unable to open minesweep process (%d).\n", GetLastError());
                    return 0;
                }

                //Read Grid
                if(ReadProcessMemory(hWinMineProc,
                                     (LPVOID)GRID_ADDRESS,
                                     (LPVOID)grid, 
                                     GRID_SIZE,
                                     &bytesWritten) == 0) {
                    printf("Unable to read process memory (%d).\n", GetLastError());        
                    return 0;
                } else {
                    //Modify Grid
                    for(x=0;x<=GRID_SIZE;x++) {
                        if((*(grid + x) & 0xff) == BOMB_HIDDEN) {
                            *(grid + x) = replacement;
                        }
                    }
                }

                //Write grid
                if(WriteProcessMemory(hWinMineProc, 
                                      (LPVOID)GRID_ADDRESS,
                                      (LPCVOID)grid, 
                                      GRID_SIZE, 
                                      &bytesWritten) == 0) {
                    printf("Unable to write process memory (%d).\n", GetLastError());        
                    return 0;
                } else {
                    printf("Grid Update Successful\n");
                }

                //Let go of minesweep
                CloseHandle(hWinMineProc);
                break;
            }

        //Get next process
        } while(Process32Next(hProcessSnap, &peProcess));   
    }
            
    if(!procFound)
        printf("WinMine Process Not Found\n");

    return 0;
}

