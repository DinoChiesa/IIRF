// Copyright (c) Microsoft Corporation, 2005, 2006, 2007.  All rights reserved.

#ifndef IIRF_CONFIG_H
#define IIRF_CONFIG_H

#include "RewriteRule.h" 

typedef struct IirfConfig {
    RewriteRule * rootRule; 
    char LogFileName[_MAX_PATH]; 
    int LogLevel;
    DWORD FilterPriority;
    boolean StrictParsing;
    int IterationLimit;
    int MaxMatchCount;
    boolean WantNotifyLog;  // setting this to TRUE will enable (SF_NOTIFY_LOG)
                            // and thus disable kernel-mode cache in IIS6
    boolean FirstLog;
    char CondSubstringBackrefFlag; 
    boolean EngineOff; 
    char * StatusUrl; 
    boolean AllowRemoteStatus; 
    int numRequestsServed;

    int nErrors;
    int nRules;
    int nWarnings;
    int nLines;
    FILETIME LastWriteOfIniFile;
    SYSTEMTIME ConfigRead ; 
    
} IirfConfig, *P_IirfConfig;

IirfConfig * ReadConfig(char * ConfigFile, int retryCount) ;

#endif
