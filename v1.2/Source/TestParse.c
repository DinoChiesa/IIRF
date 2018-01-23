#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <WTypes.h>

extern void IsapiFilterTestSetup(char * psz_iniDirName) ;


void Usage(char *appname)
{
    printf("\nTestParse.exe\n");
    printf("  tool for testing ini-file parse logic, for IIRF.\n\n");
    printf("usage:\n");
    printf("  %s <DirContainingIniFile>\n\n", appname);
}


int main(int argc, char **argv)
{
    if (argc!=2) {
	Usage(argv[0]);
	exit(1);
    }

    IsapiFilterTestSetup(argv[1]);
}
