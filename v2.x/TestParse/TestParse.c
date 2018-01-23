#include <stdio.h>

#include "IirfConfig.h"

extern IirfVdirConfig * Iirf_IsapiFilterTestSetup(char * psz_iniDirName) ;
extern char * Iirf_GetVersion(void);
extern char * Iirf_GetBuildSig(void);


char * gBuildSig = __DATE__ " " __TIME__;


void Usage(char *appname)
{
    printf("\nTestParse.exe   (built: %s)\n", gBuildSig);
    printf("  A tool for validating ini-file syntax, for IIRF. It reads in\n");
    printf("  the ini file and prints any warnings or errors found in the file.\n\n");
        printf("  The version of IIRF this tool is linked with is\n  '%s'.\n", Iirf_GetVersion());
    printf("  The IIRF library was built '%s'\n\n", Iirf_GetBuildSig());
    printf("usage:\n");
    printf("  %s <DirContainingIniFile>\n\n", appname);
}


int main(int argc, char **argv)
{
    IirfVdirConfig * cfg;

    if (argc!=2) {
        Usage(argv[0]);
        return 1;
    }

    cfg= Iirf_IsapiFilterTestSetup(argv[1]);

    return cfg->nErrors + cfg->nWarnings;
}
