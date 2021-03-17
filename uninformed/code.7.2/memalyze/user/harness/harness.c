#define  UNICODE
#include <windows.h>

int _cdecl wmain(int argc, wchar_t **argv)
{
	LoadLibrary(argv[1]);

	while (TRUE)
	{
		SleepEx(1000, TRUE);
	}

	return 0;
}
