/*

  IirfConfig.c

  Ionic's Isapi Rewrite Filter [IIRF]

  IIRF is an ISAPI Filter that does URL-rewriting.
  Inspired by Apache's mod_rewrite .
  Implemented in C, does not use MFC.

  Copyright (c) Dino Chiesa, 2005-2011.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  See the attached License.txt file, or see the Rewriter.c module for
  the details of the license for IIRF.

  Last saved: <2012-March-11 20:21:19>

  compile: cd .. && nmake CONFIG=Debug PLATFORM=x64 filter

*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <shlwapi.h>   // for PathSearchAndQualify
#include <WTypes.h>    // for DWORD, HANDLE, etc
#include <HttpFilt.h>  // HTTP_FILTER_CONTEXT, etc

#include "IIRF.h"

#define MAX_LINE_LENGTH 4096

// externs
extern CRITICAL_SECTION  gcsVdirConfig;                                                    // Rewriter.c
extern IirfServerConfig *gFilterConfig;                                                    // Rewriter.c
extern LogFileEntry * GetLogFile(IirfVdirConfig *cfg);                                     // IirfLogging.c
extern void ReleaseLogFile(LogFileEntry *e);                                               // IirfLogging.c
extern void LogMessage( IirfVdirConfig *cfg, int MsgLevel, const char *format, ... );      // IirfLogging.c
extern void CacheLogMessage( int level, const char *format, ... );                         // IirfLogging.c
extern void TRACE(char *format, ...);                                                      // IirfLogging.c
extern char * GetServerVariable_AutoFree( PHTTP_FILTER_CONTEXT pfc, char *variableName );  // ??
extern char * Iirf_AllocAndSprintf( HTTP_FILTER_CONTEXT * pfc, const char * format, ... ); // Utils.c
extern char * Iirf_AllocAndConcatenate(char *s1, char *s2);                                // Utils.c
extern char * Iirf_SystemTimeUtcToLocalTimeString(SYSTEMTIME *pSystemTime);                // Utils.c
extern char * Iirf_FileTimeToLocalTimeString(FILETIME *pFileTime);                         // Utils.c
extern void Iirf_GenErrorMessage(errno_t e, char *s, DWORD sz);                            // Utils.c
extern void Iirf_EmitEventLogEventX( WORD infoType, DWORD dwEventId, LPTSTR msg2, const char * format, ... );  // Utils.c


// typedefs for this module

/// Linked list to hold a record of ini open failures. This allows
/// IIRF to log a Windows Event just once, per ini file, so as to
/// prevent spamming the event log.
typedef struct _IniOpenFailed {
    char *physicalPath;
    struct _IniOpenFailed *next;
} IniOpenFailed;


/// Temporary structure used only during reading of a configuration.
typedef struct _ParseContext {
    IirfVdirConfig *thisConfig;
    RewriteRule *currentRule;
    RewriteRule *previousRule;
    RewriteCondition *currentCond;
    char *strtokContext;
    char *p2;
    IniFileItem *currentIni;
} ParseContext;


// globals
IirfVdirConfig *gVdirConfigList = NULL;
IniOpenFailed *gIniOpenFailures;  // lives for the lifetime of the process



BOOL AlreadyLoggedIniOpenFailure(char *fileName)
{
    IniOpenFailed *current = gIniOpenFailures;
    EnterCriticalSection(&gcsVdirConfig);
    // look for the item in the list
    while (current != NULL) {
        if (strcmp(current->physicalPath, fileName)==0) {
            TRACE("AlreadyLoggedIniOpenFailure: file='%s' TRUE", fileName);
            LeaveCriticalSection(&gcsVdirConfig);
            return TRUE;
        }
        current = current->next;
    }
    TRACE("AlreadyLoggedIniOpenFailure: file='%s' FALSE", fileName);
    LeaveCriticalSection(&gcsVdirConfig);
    return FALSE;
}


void RememberIniOpenFailure(char *fileName)
{
    IniOpenFailed *current = gIniOpenFailures, *previous;
    int count = 0;
    TRACE("RememberIniOpenFailure: file='%s'", fileName);
    EnterCriticalSection(&gcsVdirConfig);
    if (current == NULL) {
        TRACE("RememberIniOpenFailure: first one");
        gIniOpenFailures = (IniOpenFailed *) malloc(sizeof(IniOpenFailed));
        current = gIniOpenFailures;
        current->physicalPath = _strdup(fileName);
        current->next = NULL;
        LeaveCriticalSection(&gcsVdirConfig);
        return;
    }

    // find the end of the list
    while (current != NULL) {
        previous = current;
        current = current->next;
        count++;
    }

    // append the item to the list
    TRACE("RememberIniOpenFailure: count: %d", count);
    current = (IniOpenFailed *) malloc(sizeof(IniOpenFailed));
    current->physicalPath = _strdup(fileName);
    current->next = NULL;
    previous->next = current;

    LeaveCriticalSection(&gcsVdirConfig);
}


void ForgetIniOpenFailure(char *fileName)
{
    IniOpenFailed *current = gIniOpenFailures, *previous = NULL;
    int count= 0;
    TRACE("ForgetIniOpenFailure: file='%s'", fileName);

    if (current == NULL) {
        TRACE("ForgetIniOpenFailure: empty list, nothing to do.");
        return;
    }

    // optimize for the "nothing to do" case
    if (!AlreadyLoggedIniOpenFailure(fileName)) {
        TRACE("ForgetIniOpenFailure: not found list, nothing to do.");
        return;
    }

    EnterCriticalSection(&gcsVdirConfig);
    // look for the item in the list
    while (current != NULL) {
        count++;
        if (strcmp(current->physicalPath, fileName)==0) {
            TRACE("ForgetIniOpenFailure: found, item #%d.", count);
            // prune/graft
            if (previous == NULL) {
                // remove the first elt in the list
                gIniOpenFailures = current->next;
            }
            else {
                previous->next = current->next;
                free(current->physicalPath);
            }
            LeaveCriticalSection(&gcsVdirConfig);
            return;
        }
        current = current->next;
    }

    LeaveCriticalSection(&gcsVdirConfig);
    return;
}



BOOL GetLastUpdate(char *fileName, FILETIME *pFileTime)
{
    WIN32_FILE_ATTRIBUTE_DATA fi;
    ZeroMemory( &fi, sizeof(fi));

    if ( GetFileAttributesEx(fileName, GetFileExInfoStandard, &fi ) ) {
        *pFileTime = fi.ftLastWriteTime;
        return TRUE;
    }

    // set the filetime to null values
    pFileTime->dwLowDateTime = pFileTime->dwHighDateTime = 0;
    return FALSE;
}



// IIRF keeps a list of errors and warnings for each ini file.
void InsertIirfStatusMsg(IirfVdirConfig *tc, char * msg, int flavor)
{
    ArchivedStatusMessage * pm = (ArchivedStatusMessage *) malloc(sizeof(ArchivedStatusMessage));
    pm->Next = NULL;
    pm->Flavor = flavor;
    pm->Text = msg;  // assumed to be malloc'd; will be free'd later.

    // insert
    if (tc->statusMsgs == NULL) {
        // first one
        tc->statusMsgs = pm;
    }
    else {
        // walk the chain
        ArchivedStatusMessage * node = tc->statusMsgs;

        while (node->Next != NULL) {
            node = node->Next;
        }
        node->Next = pm;
    }
    return;
}




boolean IsIniChainUpdated(IirfVdirConfig *cfg, IniFileItem *root)
{
    // checks the entire chain of ini files
    boolean isUpdated= FALSE;
    FILETIME lastWrite;
    IniFileItem *item = root;

    while (item != NULL && !isUpdated) {
        BOOL result = GetLastUpdate(item->Name, &lastWrite);

        if (result) {
            // success - we got the time
            #if NOT
            char * t1 = Iirf_FileTimeToLocalTimeString(&lastWrite);
            char * t2 = Iirf_FileTimeToLocalTimeString(&(item->LastWrite));
            TRACE("IsIniChainUpdated: compare current(%s)  previous(%s)", t1, t2);
            free(t1);
            free(t2);
            #endif
            if (lastWrite.dwHighDateTime > item->LastWrite.dwHighDateTime)
                isUpdated= TRUE;
            else if ((lastWrite.dwHighDateTime == item->LastWrite.dwHighDateTime) &&
                     (lastWrite.dwLowDateTime > item->LastWrite.dwLowDateTime ))
                isUpdated= TRUE;
            LogMessage(cfg, 4, "IsIniChainUpdated: %s %s", item->Name, (isUpdated) ? "YES" : "NO");
            ForgetIniOpenFailure(item->Name);
        }
        else {
            int e = GetLastError();
            TCHAR eMsg[256];
            const char * eventMsgFormat = "IIRF: Could not open ini file '%s' (error: %d, %s)";
            Iirf_GenErrorMessage(e, eMsg, 256);
            LogMessage(cfg, 2, "IsIniChainUpdated: could not open file '%s' (error: %d, %s)",
                       item->Name, e, eMsg);
            // workitem 30566: possibly the file has been deleted
            isUpdated = TRUE;
            // workitem 30216
            if (gFilterConfig->WantEventsForIniOpen &&
                !AlreadyLoggedIniOpenFailure(item->Name)) {
                Iirf_EmitEventLogEventX(EVENTLOG_WARNING_TYPE,
                                        IIRF_EVENT_CANNOT_READ_INI,
                                        NULL,
                                        eventMsgFormat, item->Name, e, eMsg);
                RememberIniOpenFailure(item->Name);
            }
        }

        if (!isUpdated)
            isUpdated= IsIniChainUpdated(cfg, item->sibling);

        item = item->firstChild;
    }

    LogMessage(cfg, 4, "IsIniChainUpdated: return %s", (isUpdated) ? "TRUE" : "FALSE");
    return isUpdated;
}



/* Iirf_FileTimeToLocalTimeString
 *
 * Purpose:
 *
 *     Given an APPL_MD_PATH like /LM/W3SVC/3338381/ROOT/winisp, return the
 *     vdir virtual path, "/winisp".  If the path refers to the ROOT,
 *     (/LM/W3SVC/3338381/ROOT), then return "/".  The returned value is
 *     not allocated and must not be freed.
 *
 * Arguments:
 *
 *     applMdPath - char * to APPL_MD_PATH
 *
 * Returns:
 *
 *     a pointer to the vdir virtual path.  Caller must not free.
 *
 */
char * VdirFromApplMdPath(char* applMdPath)
{
    char *p1 = applMdPath;
    int i = 0;

    while (i < 4 && p1 != NULL) {
        p1 = strchr(p1+1, '/');
        i++;
    }

    if (i != 4) return "?";
    if (p1 == NULL) return ""; // vdir is at /
    return p1; // points to the 5th / in the applMdPath
}



IirfVdirConfig * NewVdirConfig(char * ConfigFile, char * ApplMdPath)
{
    // The memory for vdir configuration is not bound to a request,
    // therefore we do not want to use AllocMem().  The vdir config is
    // used by the request, but vdir config lifetime spans many requests.
    // In that case we use malloc and reference counting, coupled with
    // an expiration strategy, based on the last-mod time of the ini file.

    IirfVdirConfig *a           = (IirfVdirConfig *) malloc(sizeof(IirfVdirConfig));
    IniFileItem *item           = (IniFileItem *) malloc(sizeof(IniFileItem));
    int n                       = 0;

    a->RefCount                 = 1;
    a->Era                      = 0;
    a->rootRule                 = NULL;
    a->Expired                  = FALSE;
    a->AllowRemoteStatus        = ALLOW_REMOTE_STATUS_DEFAULT;

    // Originally I had set the default values for each field in the
    // structure, here. But in order to be able to detect and warn when
    // duplicate directives appear in the Ini file, I set these values
    // to invalid but well-known values (Zero). Then, when a directive
    // is encountered, if the current value of the setting is not the
    // well-known value, it results in a warning.
    //
    // For booleans, it's not possible to know if it's been set or not, so
    // I have an additional field in the struct Xxxx_IsSpecified, that
    // is initialized to FALSE for the 3 boolean fields.  It is set when
    // the directive is encountered.
    //
    // This means the actual default values must be set as necessary, later,
    // after the ini file has been completely read.
    // This is done in SetDefaultVdirConfigValuesAsNecessary().
    //

    a->LogLevel                      = -1;
    a->IterationLimit                = 0;
    a->MaxMatchCount                 = 0;
    a->CondSubstringBackrefFlag      = '\0';
    a->ConversionFlagChar            = '\0';
    a->StatusUrl                     = NULL;
    a->RewriteBase                   = NULL;
    a->RewriteBase_IsSpecified       = FALSE;
    a->UrlDecoding_IsSpecified       = FALSE;
    a->EngineOn_IsSpecified          = FALSE;
    a->StatusUrl_IsSpecified         = FALSE;
    a->ProxyPreserveHost_IsSpecified = FALSE;
    a->ProxyTimeout[0]               = -1;
    a->ProxyTimeout[1]               = -1;
    a->ProxyTimeout[2]               = -1;
    a->ProxyTimeout[3]               = -1;

    a->LogFileName              = NULL;
    a->ApplMdPath               = NULL;
    a->pLogFile                 = NULL;
    a->Next                     = NULL;
    a->statusMsgs               = NULL;
    a->nRules                   = 0;
    a->nWarnings                = 0;
    a->nErrors                  = 0;
    a->nLines                   = 0;
    a->nFiles                   = 0;
    a->numRequestsServed        = 0;
    a->rootMap                  = NULL;
    a->rootPpr                  = NULL;

    // set up the ini file
    a->IniChain                 = item;
    item->Name                  = (char *) malloc(MAX_PATH * sizeof(char));
    // normalize the path for the config file
    PathSearchAndQualify(ConfigFile, item->Name, MAX_PATH);
    item->lineNum               = 0;
    item->isMap                 = FALSE;
    item->file                  = NULL;
    item->parent                = NULL;
    item->firstChild            = NULL;
    item->sibling               = NULL;  // the root's sibling will always remain NULL
    GetLastUpdate(item->Name, &(item->LastWrite));

    n                           = Iirf_ConvertSizeTo32bits(strlen(ApplMdPath) +1);
    a->ApplMdPath               = (char *) malloc(n * sizeof(char));
    strcpy_s(a->ApplMdPath, n, ApplMdPath);

    a->Vdir                     = VdirFromApplMdPath(a->ApplMdPath);

    a->pCS                      = (CRITICAL_SECTION*) malloc(sizeof(CRITICAL_SECTION));
    InitializeCriticalSection(a->pCS);

    return a;
}





void ParseCondModifierFlags(IirfVdirConfig * cfg, char * pModifiers, RewriteCondition *cond)
{
    cond->LogicalOperator= 0;
    cond->IsCaseInsensitive= FALSE;

    if (pModifiers==NULL) return;  // no flags at all

    LogMessage(cfg, 3, "ParseCondModifierFlags: '%s'", pModifiers);

    if ((pModifiers[0] != '[') ||
        (pModifiers[strlen(pModifiers)-1] != ']')) {
        LogMessage(cfg, 1, "WARNING: Badly formed RewriteCond modifier flags.");
        return;
    }
    else {
        char * p1, *p2;
        char * strtokContext= NULL;
        p1= pModifiers+1;
        pModifiers[strlen(pModifiers)-1]=0; // remove trailing ']'

        p2= strtok_s(p1, ",", &strtokContext);  // split by commas
        while (p2 != NULL) {
            LogMessage(cfg, 5, "ParseCondModifierFlags: token '%s'", p2);

            if ((p2[0]=='O') && (p2[1]=='R') && (p2[2]==0)) {  // logical OR
                LogMessage(cfg, 5, "Cond: Logical OR");
                cond->LogicalOperator= 1; // this will apply to the following RewriteCond in the ini file
            }
            else if (((p2[0]=='I') && (p2[1]==0))  // case-[I]nsensitive
                     || ((p2[0]=='N') && (p2[1]=='C') && (p2[2]==0)) ) {  // [N]ot [C]ase-insensitive
                LogMessage(cfg, 5, "Cond: Case Insensitive match");
                cond->IsCaseInsensitive= TRUE;
            }
            else {
                LogMessage(cfg, 1, "WARNING: unsupported RewriteCond modifier flag '%s'", p2);
            }

            p2= strtok_s(NULL, ",", &strtokContext);  // next token
        }

    }
    return;
}




boolean ConditionsAreIdentical (IirfVdirConfig * cfg, RewriteCondition *c1, RewriteCondition *c2)
{
    // if both are NULL, then yes, they are identical
    if (c1 == NULL && c2== NULL) return TRUE;
    // if only one of them is NULL, then NO they are not identical
    if (c1 == NULL) return FALSE;
    if (c2 == NULL) return FALSE;

    // otherwise, if any of the properties differ, then NO they are not identical
    if ((c1->TestString != NULL) && (c2->TestString!= NULL) &&
        (strcmp(c1->TestString, c2->TestString)==0) &&
        (c1->IsCaseInsensitive == c2->IsCaseInsensitive) &&
        (c1->Pattern != NULL) && (c2->Pattern != NULL) &&
        (strcmp(c1->Pattern, c2->Pattern)==0) &&
        (c1->LogicalOperator == c2->LogicalOperator)
        )
        // otherwise, compare the children.
        return ConditionsAreIdentical(cfg, c1->Child, c2->Child);

    return FALSE;
}



/* IsDuplicateRule
 *
 * Purpose:
 *
 *     Checks a rule against the existing list of rules, to see if it is
 *     a duplicate. "Duplicate" means, 2 distinct rules are set to apply
 *     under the same conditions -- same rule flavor, pattern, same case
 *     insensitivity, same rule condition chain.
 *
 *     In other words, if there are 2 rules, each with the same pattern,
 *     and they redirect to a different target, then that still violates the
 *     uniqueness constraint, even though the replacement strings are different.
 *     Likewise, if one rule is a [G] (Gone) and another is [NF] (Not Found), but
 *     the pattern is the same, uniqueness is still violated.
 *
 *     This check is just a courtesy.  People can still produce rules that
 *     are equivalent, using different forms of regex syntax, and so on.  This is
 *     only intended to flag inadvertent copy/paste type errors in the ini file.
 *
 * Arguments:
 *
 *     root - the base of the chain of rules
 *
 *     rule - the new rule to check, including the condition chain if any.
 *
 *
 * Returns:
 *
 *     TRUE if the rule is a duplicate.  FALSE if not.
 *
 */

boolean IsDuplicateRule(IirfVdirConfig * cfg, RewriteRule * rule)
{
    RewriteRule * current= cfg->rootRule;
    char *h1, *p1;
    h1 = rule->HeaderToRewrite;
    p1 = rule->Pattern;

    while (current!=NULL) {
        if ((rule->RuleFlavor == current->RuleFlavor) &&            // same flavor, AND
            (strcmp(current->Pattern, p1)==0) &&                    // patterns are identical, AND
            ((rule->RuleFlavor != FLAVOR_RW_HEADER) ||              // if appropriate
             (_stricmp(h1, current->HeaderToRewrite)==0)) &&        //   the headers are identical, AND
            (rule->IsCaseInsensitive == current->IsCaseInsensitive) && // case insensitivity is the same,  AND
            ConditionsAreIdentical(cfg, rule->Condition, current->Condition)        // conditions are identical
            ) {
            return TRUE;
        }

        current= current->next; // go to the next rule in the list
    }
    return FALSE;
}



void FreeCondList(RewriteCondition * cond)
{
    if (cond == NULL)              return ;

    if (cond->RE!= NULL)           pcre_free(cond->RE);
    if (cond->TestString != NULL)  free(cond->TestString);
    if (cond->Pattern != NULL)     free(cond->Pattern);

    if (cond->Child != NULL)       FreeCondList(cond->Child);  // recurse

    free(cond);
    return;
}



void FreeRuleList (RewriteRule * ruleNode)
{
    if (ruleNode==NULL)                     return ;
    if (ruleNode->RE !=  NULL)              pcre_free(ruleNode->RE);
    if (ruleNode->HeaderToRewrite != NULL)  free(ruleNode->HeaderToRewrite);
    if (ruleNode->Pattern != NULL)          free(ruleNode->Pattern);
    if (ruleNode->Replacement != NULL)      free(ruleNode->Replacement);

    FreeCondList(ruleNode->Condition);

    if (ruleNode->next != NULL) FreeRuleList(ruleNode->next);

    free (ruleNode);
    return;
}



void InsertCond(RewriteCondition ** root, RewriteCondition * newCond)
{
    if ((*root)==NULL) {
        *root= newCond;
        return;
    }
    InsertCond( &((*root)->Child), newCond);
    return;
}



void HandleSpecialConditionVariant(char *pattern, RewriteCondition *cond)
{
    char * p1= pattern;
    if ((*p1 == '-') && ((*(p1+1)=='d') || (*(p1+1)=='f') || (*(p1+1)=='l') || (*(p1+1)=='j') || (*(p1+1)=='s')))
        cond->SpecialConditionType= *(p1+1);
    else if (*p1=='<' || *p1=='>' || *p1=='=') {
        cond->SpecialConditionType= *p1;
        // omit the comparison operator from the pattern string
        strcpy_s(cond->Pattern, strlen(pattern)+1, pattern+1);
    }
    return;
}



static char delims[]= " \n\r\t";




void LogParseMsg(char * source,
                 int flavor,
                 const char * flavorString,
                 char * fileName,
                 int lineNum,
                 ParseContext *pc,
                 const char *format,
                 va_list argp)
{
    char * msg;
    size_t len1, len2;
    const char * prefixParseMsgFormat = "%s(%d): %s: ";

    // _scprintf doesn't count terminating '\0'
    len1 = _scprintf(prefixParseMsgFormat,
                     fileName, lineNum,
                     flavorString) + 1;

    //prefix = malloc(sizeof(char) * len1);
    //sprintf_s(prefix, len1, prefixFormat, pc->currentIni->Name, pc->currentIni->lineNum);

    len2 = _vscprintf( format, argp ) + 1; // _vscprintf doesn't count terminating '\0'
    msg = (char*) malloc( (len1 + len2) * sizeof(char) );

    sprintf_s(msg, len1+len2, prefixParseMsgFormat,
              pc->currentIni->Name, pc->currentIni->lineNum,
              flavorString);
    vsprintf_s( msg+len1-1, len2+1, format, argp );
    LogMessage(pc->thisConfig, 1, "%s: %s", source, msg);
    InsertIirfStatusMsg(pc->thisConfig, msg, flavor);
}



void LogParseError(ParseContext *pc, const char *format, ... )
{
    va_list argp;
    va_start( argp, format );
    LogParseMsg("ReadVdirConfig", 0, "ERROR",
                pc->currentIni->Name,
                pc->currentIni->lineNum,
                pc, format, argp);
    pc->thisConfig->nErrors++;
    va_end(argp);
}

void LogParseWarning(ParseContext *pc, const char *format, ... )
{
    va_list argp;
    va_start( argp, format );
    LogParseMsg("ReadVdirConfig", 1, "WARNING",
                pc->currentIni->Name,
                pc->currentIni->lineNum,
                pc, format, argp);
    pc->thisConfig->nWarnings++;
    va_end(argp);
}


void LogTextMapWarning(char *fileName, int lineNum, ParseContext *pc, const char *format, ... )
{
    va_list argp;
    va_start( argp, format );
    LogParseMsg("ReadTextMap", 1, "WARNING",
                fileName, lineNum,
                pc, format, argp);
    pc->thisConfig->nWarnings++;
    va_end(argp);
}


int ParseAndApplyRuleModifierFlags(ParseContext *pc,
                                   char *directive,
                                   char *pModifiers,
                                   RewriteRule *rule)
{
    IirfVdirConfig *cfg = pc->thisConfig;
    boolean inconsistent = FALSE;

    rule->QueryStringAppend = FALSE;
    rule->ProxyPreserveHost = FALSE;
    rule->IsForbidden       = FALSE;
    rule->IsLastIfMatch     = FALSE;
    rule->IsNotFound        = FALSE;
    rule->IsGone            = FALSE;
    rule->IsCaseInsensitive = FALSE;
    rule->RecordOriginalUrl = FALSE;
    rule->IsNoIteration     = FALSE;  // WorkItem 26212
    //rule->RedirectCode= 0;

    if (pModifiers==NULL) return 0;  // no flags at all - A-OK

    LogMessage(cfg, 4, "ParseRuleModifierFlags: '%s'", pModifiers);

    if ((pModifiers[0] != '[') || (pModifiers[strlen(pModifiers)-1] != ']')) {
        LogMessage(cfg, 1, "ReadVdirConfig: Badly formed modifier flags. (%s)", pModifiers);
        return 1; // error
    }
    else {
        char * p1, *p2;
        char * strtokContext= NULL;
        p1= pModifiers+1; // skip leading '['
        pModifiers[strlen(pModifiers)-1]=0; // remove trailing ']'

        p2= strtok_s(p1, ",", &strtokContext);  // split by commas
        while (p2 != NULL) {
            LogMessage(cfg, 5, "ParseRuleModifierFlags: token '%s'", p2);

            if (p2[0]=='R' && (p2[1]=='\0' || p2[1]=='=')) {  // redirect
                if (rule->RuleFlavor != FLAVOR_RW_URL && rule->RuleFlavor != FLAVOR_REDIRECT) {
                    LogMessage(cfg, 1, "ReadVdirConfig: Cannot use R modifier with %s", directive);
                    return 1; // error
                }
                // workitem 26701
                if (rule->RuleFlavor == FLAVOR_RW_URL) {
                    // RewriteRule with [R] flag - A-OK
                    LogMessage(cfg, 1, "ReadVdirConfig: INFO: RewriteRule with R modifier - will Redirect");
                    rule->RuleFlavor= FLAVOR_REDIRECT;
                }

                // if (rule->RedirectCode != 0) {
                //     LogMessage(cfg, 1, "ReadVdirConfig: repeated R modifier");
                //     return 1; // error
                // }

                rule->RedirectCode= REDIRECT_CODE_DEFAULT;   // use the default redirect code
                if (p2[1]=='\0') { }
                else if ((p2[1]=='=') && (p2[2]!='\0')) {
                    int n= atoi(p2+2);
                    if ((n <= REDIRECT_CODE_MAX) && (n >= REDIRECT_CODE_MIN))
                        rule->RedirectCode= n;
                    else {
                        LogParseWarning(pc, "Return code (%d) out of range, using default (%d)",
                                   n, REDIRECT_CODE_DEFAULT);
                    }
                }
                else {
                    LogMessage(cfg, 1, "ReadVdirConfig: malformed R modifier");
                    return 1; // error
                }
                LogMessage(cfg, 5, "rule: Redirect(%d)", rule->RedirectCode);

            }
            else if (p2[0]=='P' && p2[1]=='\0') {  // proxy

                if (rule->RuleFlavor == FLAVOR_PROXY) {
                    LogMessage(cfg, 1, "ReadVdirConfig: INFO: ProxyPass with P modifier - redundant.");
                }
                else if (rule->RuleFlavor == FLAVOR_RW_URL) {
                    // RewriteRule with [P] flag - A-OK
                    LogMessage(cfg, 1, "ReadVdirConfig: INFO: RewriteRule with P modifier - will Proxy");
                    rule->RuleFlavor= FLAVOR_PROXY;
                }
                else {
                    LogMessage(cfg, 1, "ReadVdirConfig: Cannot use P modifier with %s", directive);
                    return 1; // error
                }
            }
            else if ((p2[0]=='F') && (p2[1]=='\0')) {  // forbidden (403)  [F]
                LogMessage(cfg, 5, "rule: Forbidden");
                rule->IsForbidden= TRUE;
            }
            else if ((p2[0]=='G') && (p2[1]=='\0')) {  // Gone (410)  [G]
                LogMessage(cfg, 5, "rule: Gone");
                rule->IsGone= TRUE;
            }
            else if ((p2[0]=='N') && (p2[1]=='F') && (p2[2]=='\0')) {  // not found (404)  [NF]
                LogMessage(cfg, 5, "rule: Not found");
                rule->IsNotFound= TRUE;
            }
            else if ((p2[0]=='P') && (p2[1]=='H') && (p2[2]=='\0')) {  // preserve host  [PH]
                LogMessage(cfg, 5, "rule: Preserve Host");
                rule->ProxyPreserveHost= TRUE;
            }
            else if ((p2[0]=='L')  && (p2[1]=='\0'))  {  // Last rule to process if match [L]
                LogMessage(cfg, 5, "rule: Last");
                rule->IsLastIfMatch= TRUE;
            }
            else if (((p2[0]=='I') && (p2[1]=='\0'))   // case-insensitive  [I]
                     || ((p2[0]=='N') && (p2[1]=='C') && (p2[2]=='\0')) )  {  // Not Case-insensitive  [NC]
                LogMessage(cfg, 5, "rule: Case Insensitive match");
                rule->IsCaseInsensitive= TRUE;
            }
            else if ((p2[0]=='U') && (p2[1]=='\0'))  {  // Unmangle URLs  [U]
                LogMessage(cfg, 5, "rule: Unmangle URLs");
                rule->RecordOriginalUrl= TRUE;
            }
            // workitem 19486
            else if ((p2[0]=='Q') && (p2[1]=='S') && (p2[2]=='A') && (p2[3]=='\0'))  {  // Query-string Append  [QSA]
                LogMessage(cfg, 5, "rule: Querystring Append");
                rule->QueryStringAppend= TRUE;
            }
            // WorkItem 26212
            else if ((p2[0]=='N') && (p2[1]=='I') && (p2[2]=='\0'))  {  // No Iteration  [NI]
                LogMessage(cfg, 5, "rule: No Iteration");
                rule->IsNoIteration= TRUE;
            }
            else {
                LogMessage(cfg, 1, "WARNING: unsupported RewriteRule modifier flag '%s'.  Ignoring this rule.", p2);
                    return 1;
            }

            p2= strtok_s(NULL, ",", &strtokContext);  // next token
        }


        // consistency checks
        if (rule->IsForbidden) {

            if (rule->RuleFlavor==FLAVOR_REDIRECT) {
                LogMessage(cfg, 1, "WARNING: Inconsistent modifier; [F] on a Redirect");
                inconsistent = TRUE;
            }
            if (rule->IsLastIfMatch) {
                LogMessage(cfg, 1, "WARNING: Redundant modifier flags - F,L");
                inconsistent = TRUE;
            }
            if (rule->IsNotFound) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - F,NF");
                inconsistent = TRUE;
            }
            if (rule->IsGone) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - F,G");
                inconsistent = TRUE;
            }
            if (rule->QueryStringAppend) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - F,QSA");
                inconsistent = TRUE;
            }
            if (rule->IsNoIteration) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - F,NI");
                inconsistent = TRUE;
            }
        }

        if (rule->IsNotFound) {
            if (rule->IsLastIfMatch) {
                LogMessage(cfg, 1, "WARNING: Redundant modifier flags - NF,L");
                inconsistent = TRUE;
            }
            if (rule->RuleFlavor==FLAVOR_REDIRECT) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - NF,R");
                inconsistent = TRUE;
            }
            if (rule->QueryStringAppend) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - NF,QSA");
                inconsistent = TRUE;
            }
            if (rule->IsGone) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - NF,G");
                inconsistent = TRUE;
            }
            if (rule->IsNoIteration) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - NF,NI");
                inconsistent = TRUE;
            }
        }

        if (rule->IsGone) {
            if (rule->QueryStringAppend) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - G,QSA");
                inconsistent = TRUE;
            }
            if (rule->IsLastIfMatch) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - G,L");
                inconsistent = TRUE;
            }
            if (rule->IsNoIteration) {
                LogMessage(cfg, 1, "WARNING: Inconsistent modifier flags - G,NI");
                inconsistent = TRUE;
            }
        }

        if (rule->IsLastIfMatch) {
            if (rule->IsNoIteration) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flags - L,NI");
                inconsistent = TRUE;
            }
        }

        if (rule->RuleFlavor==FLAVOR_REDIRECT) {
            if(rule->IsLastIfMatch) {
                LogMessage(cfg, 1, "INFO: Redundant modifier flag; [L] on a Redirect");
            }
            if(rule->IsNoIteration) {
                LogMessage(cfg, 1, "WARNING: Inconsistent modifier flag; [NI] on a Redirect");
                inconsistent = TRUE;
            }
        }

        if (rule->RuleFlavor==FLAVOR_PROXY) {
            if (rule->IsLastIfMatch) {
                LogMessage(cfg, 1, "INFO: Redundant modifier flag; [L] on a Proxy");
            }
            if (rule->IsNotFound) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flag - [NF] on a Proxy rule");
                inconsistent = TRUE;
            }
            if (rule->IsGone) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flag - [G] on a Proxy rule");
                inconsistent = TRUE;
            }
            if (rule->IsForbidden) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flag - [F] on a Proxy rule");
                inconsistent = TRUE;
            }
            if (rule->IsNoIteration) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flag - [NI] on a Proxy rule");
                inconsistent = TRUE;
            }
        }
        else {
            if (rule->ProxyPreserveHost) {
                LogMessage(cfg, 1, "WARNING: Conflicting modifier flag - [PH] on a non-Proxy rule");
                inconsistent = TRUE;
            }
        }

        if (inconsistent)
            return 1;
    }
    return 0;
}




void ParseDirective_LogLevel(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char *pLevel = strtok_s (NULL, delims, &(pc->strtokContext));

    if (tc->LogLevel != -1) {
        LogParseWarning(pc, "multiple %s directives. Don't do this.",
                   DIRECTIVE_REWRITE_LOG_LEVEL);
    }

    if (pLevel!=NULL) tc->LogLevel= atoi(pLevel);
    else {
        LogParseWarning(pc, "missing value.");
        tc->LogLevel= LOG_LEVEL_DEFAULT;
    }

    // validate
    if (tc->LogLevel < 0 || tc->LogLevel > 10) {
        LogParseWarning(pc, "invalid LogLevel. Valid range is (0,10). Using default value.");
        tc->LogLevel= LOG_LEVEL_DEFAULT;
    }

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): LogLevel = %d",
               pc->currentIni->Name,
               pc->currentIni->lineNum, tc->LogLevel);
}



void ParseDirective_LogFile(ParseContext *pc, size_t lineLength)
{
    char *pLogFileStub = pc->p2 + strlen(pc->p2) + 1;
    char *p3;
    char *p4;
    int count = MAX_PATH;
    char * tstr1= NULL;
    char * tstr2= NULL;
    int n;

    if (lineLength <= strlen(pc->p2)) {
        LogParseWarning(pc, "you did not specify a logfile");
        return;
    }

    if (pLogFileStub==NULL) {
        LogParseWarning(pc, "bad logfile name format");
        return;
    }

    // work item 8433
    // handle logfile stubs that contain spaces.
    p3= pLogFileStub;
    p4= pLogFileStub + strlen(pLogFileStub) - 1;

    while((*p3 == ' ')||(*p3 == '\t')) p3++;       // skip leading spaces and TABs
    while((*p4 == ' ')||(*p4 == '\n')||(*p4 == '\r')||(*p4 == '\t')) *p4--='\0'; // trim trailing spaces

    if (*pLogFileStub=='\0') {
        LogParseWarning(pc, "you did not specify a logfile");
        return;
    }

    tstr1 = (char *) malloc(MAX_PATH*2);
    tstr2 = (char *) malloc(MAX_PATH);

    // no leak when duplicate directives
    if (pc->thisConfig->LogFileName!=NULL) free(pc->thisConfig->LogFileName);

    // workitem 24567 -- allow relative paths.  This segment of
    // code appends 2 paths together and normalizes (and, I
    // believe, canonicalizes) the result. If the logfile filespec
    // is an absolute or relative path, this results in the correct
    // normalized path being used.
    strcpy_s(tstr1, MAX_PATH*2, pc->currentIni->Name);
    PathRemoveFileSpec(tstr1);
    PathAppend(tstr1, p3);
    PathSearchAndQualify (tstr1, tstr2, count);

    // count chars for the logfilename
    n = _scprintf( "%s.%d.log", tstr2, GetCurrentProcessId() ) +1;
    pc->thisConfig->LogFileName = (char*) malloc(n * sizeof(char));

    //  format logfile
    sprintf_s( pc->thisConfig->LogFileName, n,
               "%s.%d.log", tstr2, GetCurrentProcessId() );

    GetLogFile(pc->thisConfig);
    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: actual log file '%s'", pc->thisConfig->LogFileName);
    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: ini file: '%s'", pc->currentIni->Name);

    p4= Iirf_FileTimeToLocalTimeString(&(pc->currentIni->LastWrite));
    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: ini file timestamp: %s", p4);
    free(p4);

    // first chance we've had to emit the pointer for this config, and the log level
    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: cfg(0x%08X)", pc->thisConfig);
    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: LogLevel = %d", pc->thisConfig->LogLevel);

    free(tstr1);
    free(tstr2);
}




void ParseDirective_RewriteRule(ParseContext *pc)
{
    int errorOffset;
    const char *error;
    char *pHeaderToRewrite= NULL;
    char *pPattern ;
    char *pReplacement;
    char *pModifiers;
    char *directive;
    int PcreOptions= 0;
    int flavor = FLAVOR_NONE;
    int rc=0;
    size_t L1;
    RewriteRule *rule = NULL;

    if ((_stricmp(pc->p2,DIRECTIVE_REWRITE_RULE)==0) ||
        (_stricmp(pc->p2,DIRECTIVE_REDIRECT_RULE)==0) ||
        (_stricmp(pc->p2,DIRECTIVE_PROXY_PASS)==0)) {
        // (RewriteRule|RedirectRule|ProxyPass) Pattern Replacement ModiferFlags
        pPattern = strtok_s(NULL, delims, &(pc->strtokContext));
        pReplacement = strtok_s(NULL, delims, &(pc->strtokContext));
        pModifiers = strtok_s(NULL, delims, &(pc->strtokContext));

        if (_stricmp(pc->p2,DIRECTIVE_REWRITE_RULE)==0) {
            directive = DIRECTIVE_REWRITE_RULE;
            flavor = FLAVOR_RW_URL;
        }
        else if (_stricmp(pc->p2,DIRECTIVE_REDIRECT_RULE)==0) {
            directive = DIRECTIVE_REDIRECT_RULE;
            flavor = FLAVOR_REDIRECT;
        }
        else {
            directive = DIRECTIVE_PROXY_PASS;
            flavor = FLAVOR_PROXY;
        }

        LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): %s (rule %d)  '%s'  '%s' %8s",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum, directive, pc->thisConfig->nRules+1, pPattern, pReplacement,  pModifiers );

        // There are distinct directives for Rewrite, Redirect, and Proxy.
        // But, through various flags on RewriteRule, the RewriteRule syntax,
        // can be used to request either a Proxy [P] or a Redirect [R]
        //
        // The "directive" may actually change further down, depending on
        // those flags.
    }
    else {
        // RewriteHeader Header Pattern Replacement ModiferFlags
        pHeaderToRewrite = strtok_s(NULL, delims, &(pc->strtokContext));
        pPattern = strtok_s(NULL, delims, &(pc->strtokContext));
        pReplacement = strtok_s(NULL, delims, &(pc->strtokContext));
        pModifiers = strtok_s(NULL, delims, &(pc->strtokContext));
        directive = DIRECTIVE_REWRITE_HEADER;
        flavor = FLAVOR_RW_HEADER;

        LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): RewriteHeader (rule %d)  '%s'  '%s'  '%s' %8s",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum, pc->thisConfig->nRules+1, pHeaderToRewrite, pPattern, pReplacement,  pModifiers );
    }

    // Validation: Pattern and Replacement must both be non-null.  Ok
    // for Modifiers to be empty (null).
    if ((pPattern == NULL) || (pReplacement==NULL)) {
        LogParseError(pc, "bad rule format. specify a pattern and a replacement string.");
        return;
    }

    L1 = strlen(pReplacement);
    if (pReplacement[0]=='[' && pReplacement[L1-1]==']') {
        LogParseWarning(pc, "replacement string (%s) looks like a modifer - Are you sure?",
                        pReplacement);
    }

    rule = (RewriteRule *) malloc(sizeof(RewriteRule));
    rule->RuleFlavor = flavor;
    // use the default redirect code, pending modifiers
    rule->RedirectCode= REDIRECT_CODE_DEFAULT;

    rule->HeaderToRewrite= NULL;
    if (pHeaderToRewrite != NULL) {
        int len = Iirf_ConvertSizeTo32bits(strlen(pHeaderToRewrite));
        if (pHeaderToRewrite[strlen(pHeaderToRewrite)-1] != ':' &&
            // workitem 26969
            _stricmp(pHeaderToRewrite, "method")!=0 &&
            _stricmp(pHeaderToRewrite, "url")!=0) {
            // we need a colon
            rule->HeaderToRewrite= (char*) malloc(len+2);
            strcpy_s(rule->HeaderToRewrite, len+1, pHeaderToRewrite);
            rule->HeaderToRewrite[len]=':';
            rule->HeaderToRewrite[len+1]='\0';
        }
        else {
            // there is a colon
            rule->HeaderToRewrite= _strdup(pHeaderToRewrite);
        }

        // workitem 26991
        if (_stricmp(rule->HeaderToRewrite, "version:")==0) {
            LogParseError(pc, "you cannot rewrite the VERSION header");
            free(rule);
            return;
        }
    }

    rule->Pattern     = _strdup(pPattern);
    rule->Replacement = _strdup(pReplacement);
    rule->Condition   = pc->currentCond; // currentCond is possibly NULL
    rule->RE          = NULL;            // initialize in case we call FreeRuleList()
    rule->next        = NULL;            // ditto
    pc->currentCond   = NULL;            // this cond has been used, so forget it.

    // Parse and apply the rule modifier flags --
    //  this may change RuleFlavor from RW_URL to REDIRECT or PROXY.
    rc= ParseAndApplyRuleModifierFlags(pc, directive, pModifiers, rule);
    if (rc) {
        LogParseError(pc,"invalid modifiers, Ignoring that rule.");
        FreeRuleList(rule);
        return;
    }

    // Redirect to -  (unchanged)
    if (pReplacement[0]=='-' && pReplacement[0]=='\0' && rule->RuleFlavor == FLAVOR_REDIRECT) {
        LogParseError(pc,
                      "infinite loop detected: redirect to self. Ignoring that rule.");
        FreeRuleList(rule);
        return;
    }

    // check for duplicates
    if (IsDuplicateRule(pc->thisConfig, rule)) {
        LogParseError(pc,"duplicate rule. Ignoring it.");
        FreeRuleList(rule);
        return;
    }

    LogMessage(pc->thisConfig, 6, "ReadVdirConfig: not a duplicate rule...");

    // More validation
    // check if http{s}:// for RewriteRule.
    if ( rule->RuleFlavor == FLAVOR_RW_URL  &&
         (_strnicmp(pReplacement,"http://", strlen("http://"))==0  ||
          _strnicmp(pReplacement,"https://", strlen("https://"))==0 ) ) {
        LogParseWarning(pc, "Rewriting to a fully-"
                        "qualified URL. Probably wrong. You may want RedirectRule or ProxyPass.");
    }

    // check if NOT http{s}:// for redirect or proxy
    else if ( (rule->RuleFlavor == FLAVOR_REDIRECT || rule->RuleFlavor == FLAVOR_PROXY)  &&
             (_strnicmp(pReplacement,"http://", strlen("http://"))!=0  &&
              _strnicmp(pReplacement,"https://", strlen("https://"))!=0 )) {
        LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): INFO: the %s target "
                   "does not include an http(s):// scheme.",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum,
                   (rule->RuleFlavor==FLAVOR_PROXY)? "Proxy" : "Redirect");

        LogMessage(pc->thisConfig, 1, "ReadVdirConfig: The rule will %s to a target on the local machine",
                   (rule->RuleFlavor==FLAVOR_PROXY)? "Proxy" : "Redirect");
    }

    if (rule->IsCaseInsensitive) PcreOptions |= PCRE_CASELESS;

    // Compile the regex here, and store the result
    rule->RE= pcre_compile(pPattern,         // the pattern
                           PcreOptions,      // options for the regex
                           &error,           // for any error message
                           &errorOffset,     // for error offset
                           NULL);            // use default character tables

    if (rule->RE == NULL) {
        LogParseError(pc,
                      "compilation of %s expression '%s' failed at offset %d: %s",
                      directive, pPattern, errorOffset, error);
        LogMessage(pc->thisConfig, 1, "ReadVdirConfig: Ignoring that rule.");
        FreeRuleList(rule);
        return;
    }

    // insert the rule into the chain
    pc->thisConfig->nRules++;
    pc->previousRule= pc->currentRule;  // for the first rule, this is NULL.
    pc->currentRule= rule;
    if (pc->previousRule!=NULL)
        pc->previousRule->next= pc->currentRule;

    if (pc->thisConfig->rootRule==NULL) pc->thisConfig->rootRule= rule;
}


BOOL IsUniqueKeyName(IirfVdirConfig *cfg, TextMap *textMap, char *keyName)
{
    int i;
    for (i = 0; i < textMap->length && (textMap->items[i].key != NULL); ++i) {
        if (strcmp(textMap->items[i].key, keyName)==0) return FALSE;
    }

    return TRUE;
}



// IIRF keeps a list of files that contain the configuration.  The
// timestamp on these files is checked with each request that arrives,
// and a new configuration is read in when the timestamps of any of the
// files changes.
void InsertIniItem(ParseContext *pc, IniFileItem *item)
{
    item->parent = pc->currentIni;
    if (item->parent->firstChild == NULL) {
        item->parent->firstChild = item;
    }
    else {
        // walk the chain of siblings
        IniFileItem * node = item->parent->firstChild;
        while (node->sibling != NULL) {
            node = node->sibling;
        }
        node->sibling = item;
    }

    item->firstChild = NULL;
    item->sibling = NULL;
    GetLastUpdate(item->Name, &(item->LastWrite));
    return;
}



// workitem 31414
//
// Comparison function for use in qsort and bsearch. The first parameter
// is a pointer to the key for the search and the second parameter is a
// pointer to the array element to be compared with the key.
int Iirf_FindMapItemByKey( char ** key, TextMapItem *item )
{
    return _strcmpi( *key, item->key );
}



BOOL ReadTextMap(ParseContext *pc, char *fileName, RewriteMap *map)
{
    FILE * file;
    unsigned char * buffer;
    char *p1, *key, *value, *remainder, *strtokContext;
    TextMap *textMap;
    int lineNum=0, itemCount, pass, n;
    char *tstr1 = (char*) malloc(MAX_PATH*2);
    char *tstr2 = (char*) malloc(MAX_PATH);
    IirfVdirConfig *cfg = pc->thisConfig;
    IniFileItem *item;

    // normalize and/or canonicalize the path.
    strcpy_s(tstr1, MAX_PATH*2, pc->currentIni->Name);
    PathRemoveFileSpec(tstr1);
    PathAppend(tstr1, fileName);
    PathSearchAndQualify (tstr1, tstr2, MAX_PATH);
    free(tstr1);

    buffer = (unsigned char *) malloc(MAX_LINE_LENGTH);
    // do it in 2 passes, so we know how much to allocate
    for (pass = 0; pass < 2; pass++) {
        itemCount = 0;
        n= fopen_s(&file, tstr2, "r");

        if (n!=0) {
            int e = n; // GetLastError();
            char eMsg[256];
            Iirf_GenErrorMessage(e, eMsg, 256);
            LogParseError(pc, "cannot open text map file %s: error %d, %s",
                       tstr2, e, eMsg);
            free(tstr2);
            if (pass==1) {
                free(textMap->items);
                free(textMap);
            }
            return FALSE;
        }

        while (TRUE) {
            lineNum++;
            if (fgets((char *)buffer, MAX_LINE_LENGTH, file) == NULL) {
                fclose(file);
                break;
            }
            p1 = buffer;
            while (isspace(*p1)) p1++; // skip spaces
            if (*p1 == 0) continue;    // empty line
            if (*p1 == '#') continue;  // comment

            key = strtok_s(p1, delims, &strtokContext);
            value = strtok_s(NULL, delims, &strtokContext);
            remainder = strtok_s(NULL, delims, &strtokContext);

            if (pass==0) {
                LogMessage(cfg, 1, "ReadTextMap: %s(%d): key(%s) value(%s)",
                       tstr2, lineNum, key, value);
            }

            if ((remainder!=NULL) && (remainder[0]!='#')) {
                LogTextMapWarning(tstr2, lineNum,
                                  pc, "junk follows map key and value (%s)",
                                  remainder);
                continue;
            }
            else if ((key==NULL) || (value==NULL)) {
                LogTextMapWarning(tstr2, lineNum,
                                  pc, "bad format key(%s) value(%s)",
                                  key, value);
                continue;
            }
            else if (pass == 1) {
                if (!IsUniqueKeyName(cfg, textMap, key)) {
                    LogTextMapWarning(tstr2, lineNum,
                                      pc, "duplicate key (%s) in map (%s). Will never match.",
                                      key, map->name);
                }
                textMap->items[itemCount].key = _strdup(key);
                textMap->items[itemCount].nValues = 0;
                textMap->items[itemCount].indexes = NULL;
                if (map->type == 0) {
                    // txt
                    textMap->items[itemCount].value = _strdup(value);
                }
                else {
                    // rnd
                    TextMapItem *tmitem = &(textMap->items[itemCount]);
                    int length = Iirf_ConvertSizeTo32bits(strlen(value) + 2);  // double-terminated
                    char *tstr3 = (char*) malloc(length);
                    char *p3;
                    int t;

                    strcpy_s(tstr3, length, value);
                    tstr3[length-2]='\0';
                    tstr3[length-1]='\0';
                    tmitem->value = tstr3;

                    // build the list of indexes in two passes:
                    // 1st to count, 2nd to do.
                    for (t=0; t<2;  t++) {
                        tmitem->nValues = 0;
                        p3 = tstr3;
                        if (t==1)
                            tmitem->indexes[0]= 0;

                        while(TRUE) {
                            p3++;
                            if (*p3 == '\0') break;
                            if (*p3 == '|') {
                                tmitem->nValues++;
                                if (t==1) {
                                    *p3= '\0';
                                    tmitem->indexes[tmitem->nValues]= Iirf_ConvertSizeTo32bits(p3-tstr3+1);
                                }
                            }
                        }

                        if (t==0) {
                            tmitem->nValues++;
                            tmitem->indexes = calloc(tmitem->nValues, sizeof(int));
                        }
                    }
                }
            }
            itemCount++;
        }

        fclose(file);

        if (pass == 0) {
            textMap = (TextMap*) malloc(sizeof(TextMap));
            textMap->fileName = tstr2;
            textMap->length = itemCount;
            textMap->items = (TextMapItem *) calloc(itemCount, sizeof(TextMapItem));
        }
    }

    // workitem 31414:
    // qsort the map items, so later IIRF can use bsearch to retrieve
    qsort( (void *)textMap->items,
           textMap->length,
           sizeof( TextMapItem ),
           (int (*)(const void*, const void*)) Iirf_FindMapItemByKey );

    map->u.textMap = textMap;
    free(buffer);

    // Append the mapfile to the linked list of files to check
    // for mtime update, for each request.
    item = (IniFileItem *) malloc(sizeof(IniFileItem));
    item->Name       = _strdup(tstr2); // must free later in FreeIniFileChain()
    item->lineNum    = lineNum;
    item->isMap      = TRUE;
    item->parent     = NULL;
    item->firstChild = NULL;
    item->sibling    = NULL;
    GetLastUpdate(item->Name, &(item->LastWrite));
    InsertIniItem(pc, item);

    return TRUE;
}



void FreeRewriteMap(IirfVdirConfig *cfg, RewriteMap *map)
{
    RewriteMap * next;
    do {
        next = map->next;
        free(map->name);

        if (map->type == 0 || map->type == 1) { // txt or rnd
            int i;
            TextMap *textMap = map->u.textMap;
            for (i = 0; i < textMap->length; i++) {
                if (map->type == 1) // rnd
                    free(textMap->items[i].indexes);

                free(textMap->items[i].key);
                free(textMap->items[i].value);
            }

            free(textMap->fileName);
            free(textMap->items);
            free(textMap);
        }

        free(map);

        map= next;

    } while (map!=NULL);

    return;
}


void FreeProxyPassReverse(IirfVdirConfig *cfg, ProxyPassReverse *ppr)
{
    ProxyPassReverse * next;
    do {
        next = ppr->next;
        free(ppr->url);
        free(ppr->path);
        free(ppr);
        ppr= next;
    } while (ppr!=NULL);
    return;
}



BOOL IsUniqueMapName(IirfVdirConfig *cfg, char *mapName)
{
    RewriteMap *m = cfg->rootMap;
    // TRUE == Unique
    while (m != NULL) {
        if (strcmp(m->name, mapName)==0) return FALSE;
        m = m->next;
    }
    return TRUE;
}



void ParseDirective_RewriteMap(ParseContext *pc)
{
    char *pMapName = strtok_s(NULL, delims, &(pc->strtokContext));
    char *pTypeAndSource;
    char *p3;
    char *p4;
    RewriteMap * newMap= NULL;

    if (pMapName == NULL) {
        LogParseError(pc, "found RewriteMap, but no map name");
        return;
    }

    pTypeAndSource = pMapName + strlen(pMapName) + 1;
    p3= pTypeAndSource;
    p4= pTypeAndSource + strlen(pTypeAndSource) - 1;

    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): RewriteMap   %s  %s",
               pc->currentIni->Name,
               pc->currentIni->lineNum, pMapName, pTypeAndSource );

    if (pc->currentCond!=NULL) {
        LogParseError(pc, "found RewriteMap, but there is a pending RewriteCond");
        return;
    }

    if (pMapName==NULL) {
        LogParseError(pc, "bad map name");
        return;
    }

    if (pTypeAndSource==NULL) {
        LogParseError(pc, "bad map spec");
        return;
    }

    while((*p3 == ' ')||(*p3 == '\t')) p3++;       // skip leading spaces and TABs
    while((*p4 == ' ')||(*p4 == '\n')||(*p4 == '\r')||(*p4 == '\t')) *p4--='\0'; // trim trailing spaces

    pTypeAndSource = p3;
    if (*p3 == '\0') {
        LogParseError(pc, "no map spec");
        return;
    }

    // skip to the first colon
    while((*p3 != ':') && (*p3 != '\0')) p3++;
    if (*p3 == '\0') {
        LogParseError(pc, "bad map spec - no colon");
        return;
    }

    *p3='\0'; // terminate the "type" string

    if (_strnicmp(pTypeAndSource, "txt", 3)!=0 &&
        _strnicmp(pTypeAndSource, "rnd", 3)!=0) {
        LogParseError(pc, "unsupported map type (%s). Ignored.",
                      pTypeAndSource);
        return;
    }

    if (!IsUniqueMapName(pc->thisConfig, pMapName)) {
        LogParseError(pc, "duplicate map name (%s).", pTypeAndSource);
        return;
    }

    p3++; // advance to source (filename)

    newMap = (RewriteMap *) malloc(sizeof(RewriteMap));
    newMap->name = _strdup(pMapName);
    newMap->type = (_strnicmp(pTypeAndSource, "rnd", 3)==0)? 1 : 0; // txt = 0, rnd = 1
    newMap->next = NULL;

    if (!ReadTextMap(pc, p3, newMap)) {
        //  error
        free(newMap->name);
        free(newMap);
        return;
    }

    // Insert this new map into the current vdirconfig.
    if (pc->thisConfig->rootMap == NULL) {
        pc->thisConfig->rootMap = newMap;
    }
    else {
        RewriteMap * curMap= pc->thisConfig->rootMap;
        while (curMap->next != NULL)
            curMap = curMap->next;
        curMap->next = newMap;
    }

    return;
}



void ParseDirective_ProxyPassReverse(ParseContext *pc)
{
    // ProxyPassReverse  [path]   url
    IirfVdirConfig * tc = pc->thisConfig;
    char * pArg0 = strtok_s(NULL, delims, &(pc->strtokContext));  // path, if pArg1 is non-NULL. Else url
    char * pArg1 = strtok_s(NULL, delims, &(pc->strtokContext));  // url, if non-null
    char * path = NULL;
    char * url = NULL;
    ProxyPassReverse * newPpr = NULL;

    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): ProxyPassReverse   %s  %s",
               pc->currentIni->Name,
               pc->currentIni->lineNum,
               (pArg0)? pArg0 : "(--)",
               (pArg1)? pArg1 : "(--)");

    if (pc->currentCond!=NULL) {
        LogParseError(pc, "found ProxyPassReverse, but there is a pending RewriteCond");
        return;
    }

    if (pArg1 == NULL) {
        url = pArg0;
        path = "";  // empty string
    }
    else {
        url = pArg1;
        path = pArg0;
    }

    if (_strnicmp(url, "http://", 7)!=0 && _strnicmp(url, "https://", 8)!=0) {
        LogParseError(pc, "URL must begin with http(s)");
        return;
    }

    newPpr       = (ProxyPassReverse*) malloc(sizeof(ProxyPassReverse));
    newPpr->url  = _strdup(url);
    newPpr->path = _strdup(path);
    newPpr->L1   = Iirf_ConvertSizeTo32bits(strlen(newPpr->url));
    newPpr->next = NULL;

    // Insert this new Ppr into the current vdirconfig.
    if (pc->thisConfig->rootPpr == NULL) {
        pc->thisConfig->rootPpr = newPpr;
    }
    else {
        ProxyPassReverse * curPpr= pc->thisConfig->rootPpr;
        while (curPpr->next != NULL)
            curPpr = curPpr->next;
        curPpr->next = newPpr;
    }

    return;
}


void ParseDirective_IterationLimit(ParseContext *pc)
{
    IirfVdirConfig *tc = pc->thisConfig;
    char *pLimit = strtok_s(NULL, delims, &(pc->strtokContext));
    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s",
               pc->currentIni->Name,
               pc->currentIni->lineNum, DIRECTIVE_ITERATION_LIMIT, pLimit);

    if (tc->IterationLimit != 0) {
        LogParseWarning(pc, "multiple %s directives. Don't do this.",
                   DIRECTIVE_ITERATION_LIMIT);
    }

    if (pLimit!=NULL) {
        tc->IterationLimit= atoi(pLimit);
        // validate the value
        if (tc->IterationLimit > ITERATION_LIMIT_MAX ||
            tc->IterationLimit < ITERATION_LIMIT_MIN) {
            tc->IterationLimit= ITERATION_LIMIT_DEFAULT;
            LogParseWarning(pc, "Out of range "
                       "(%d <= x <= %d); setting Iteration Limit to the default= %d",
                            ITERATION_LIMIT_MIN, ITERATION_LIMIT_MAX, tc->IterationLimit);
        }
    }
    else {
        tc->IterationLimit= ITERATION_LIMIT_DEFAULT;
        LogParseError(pc, "Did not find valid limit value - "
                      "setting Iteration Limit to the default= %d",
                      tc->IterationLimit);
    }
}



void ParseDirective_MaxMatchCount(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char *pCount = strtok_s(NULL, delims, &(pc->strtokContext));
    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s",
               pc->currentIni->Name,
               pc->currentIni->lineNum, DIRECTIVE_MAX_MATCH_COUNT, pCount);

    if (tc->MaxMatchCount != 0) {
        LogParseWarning(pc, "multiple %s directives. Don't do this.",
                        DIRECTIVE_MAX_MATCH_COUNT);
    }

    if (pCount!=NULL) {
        tc->MaxMatchCount= atoi(pCount);
        // validate the value
        if (tc->MaxMatchCount > MAX_MATCH_COUNT_MAX ||
            tc->MaxMatchCount < MAX_MATCH_COUNT_MIN) {
            tc->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;
            LogParseWarning(pc, "Out of range (%d <= x <= %d); "
                            "setting MaxMatchCount to the default= %d",
                            MAX_MATCH_COUNT_MIN,
                            MAX_MATCH_COUNT_MAX,
                            tc->MaxMatchCount);
        }
    }
    else {
        tc->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;
        LogParseError(pc, "MaxMatchCount value is missing. "
                      "MaxMatchCount is now= %d",
                      tc->MaxMatchCount);
    }
}


void ParseDirective_ProxyTimeouts(ParseContext *pc, char *p1, size_t lineLength)
{
    IirfVdirConfig * tc = pc->thisConfig;
    int i;
    char *pValue = ((pc->p2 - p1 + strlen(pc->p2) + 1) >= lineLength)
        ? "null"
        : (pc->p2 + strlen(pc->p2) + 1) ;

    while((*pValue == ' ')||(*pValue == '\t')) pValue++; // skip leading spaces and TABs

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s",
               pc->currentIni->Name,
               pc->currentIni->lineNum,
               DIRECTIVE_PROXY_TIMEOUTS,
               (pValue[0])? pValue : "null");

    for (i=0; i < 4; i++) {
        if (tc->ProxyTimeout[i] != -1) {
            LogParseWarning(pc, "multiple %s directives. Don't do this.",
                            DIRECTIVE_PROXY_TIMEOUTS);
            break;
        }

        pValue = strtok_s(NULL, delims, &(pc->strtokContext));
        if (pValue == NULL) {
            LogParseError(pc, "at least one %s value is missing.",
                       DIRECTIVE_PROXY_TIMEOUTS);
            break;
        }

        // validate the value
        if (pValue[0] < '0' || pValue[0] > '9') {
            tc->ProxyTimeout[i]= HTTP_TIMEOUT_DEFAULT;
            LogParseWarning(pc, "bad value for timeout (%s); "
                            "setting proxy timeout to the default (%d)",
                            pValue,
                            tc->ProxyTimeout[i]);
        }
        else {
            tc->ProxyTimeout[i] = atoi(pValue);

            if (strcmp(pValue, "-")==0 ||
                tc->ProxyTimeout[i] > HTTP_TIMEOUT_MAX ||
                tc->ProxyTimeout[i] < HTTP_TIMEOUT_MIN) {
                tc->ProxyTimeout[i]= HTTP_TIMEOUT_DEFAULT;
                if (strcmp(pValue, "-")!=0) {
                    LogParseWarning(pc, "Out of range (%d <= x <= %d); "
                               "setting proxy timeout to the default (%d)",
                               HTTP_TIMEOUT_MIN,
                               HTTP_TIMEOUT_MAX,
                               tc->ProxyTimeout[i]);
                }
            }
        }
    }

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): Proxy Timeout Values IN SECONDS are now: Resolve=%d, Connect=%d, Send=%d, Receive=%d",
               pc->currentIni->Name,
               pc->currentIni->lineNum,
               tc->ProxyTimeout[0],
               tc->ProxyTimeout[1],
               tc->ProxyTimeout[2],
               tc->ProxyTimeout[3]);
}


void ParseDirective_CondSubstringFlag(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char *pFlag = strtok_s (NULL, delims, &(pc->strtokContext));

    if (pFlag == NULL) {
        LogParseError(pc, "incomplete %s directive: you didn't specify a character",
                      DIRECTIVE_COND_SUBSTRING_FLAG);
        return ;
    }

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s",
               pc->currentIni->Name,
               pc->currentIni->lineNum, DIRECTIVE_COND_SUBSTRING_FLAG, pFlag);

    if (tc->CondSubstringBackrefFlag != '\0') {
        LogParseWarning(pc, "you've either used multiple %s directives, or you've used both %s and %s. Don't do this.",
                   DIRECTIVE_COND_SUBSTRING_FLAG,
                   DIRECTIVE_FLAG_CHARS,
                   DIRECTIVE_COND_SUBSTRING_FLAG);
    }

    if (pFlag!=NULL) {
        if ( (*pFlag == '%') ||
             (*pFlag == '@') ||
             (*pFlag == '*') ||
             (*pFlag == '_') ||
             (*pFlag == '^') ||
             (*pFlag == '!') ||
             (*pFlag == '~'))
            tc->CondSubstringBackrefFlag= pFlag[0];
        else {
            LogParseError(pc, "illegal CondSubstringBackrefFlag (%c) - legal values are %%,@,!,~,*,_,^",
                       pFlag[0]);
        }
    }
}



void ParseDirective_FlagCharacters(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    int i;
    //char *pFlagSet = strtok_s (NULL, delims, &(pc->strtokContext));
    char *flagChars[2] = { &tc->CondSubstringBackrefFlag,
                           &tc->ConversionFlagChar};
    char defaultValues[2] = { COND_SUBSTRING_BACKREF_FLAG_DEFAULT,
                              CONVERSION_FLAG_DEFAULT};
    char *pFlag = (pc->p2 + strlen(DIRECTIVE_FLAG_CHARS) + 1);

    while((*pFlag == ' ')||(*pFlag == '\t')) pFlag++; // skip leading spaces and TABs

    for (i=0; i < sizeof(flagChars)/sizeof(flagChars[0]); i++) {
        if (i==0) {
            LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s",
                       pc->currentIni->Name,
                       pc->currentIni->lineNum, DIRECTIVE_FLAG_CHARS, pFlag);

            if (tc->CondSubstringBackrefFlag != '\0') {
                LogParseWarning(pc, "you've either used multiple %s directives, or you've used both %s and %s. Don't do this.",
                           DIRECTIVE_FLAG_CHARS,
                           DIRECTIVE_COND_SUBSTRING_FLAG,
                           DIRECTIVE_FLAG_CHARS);
            }

            if (tc->ConversionFlagChar != '\0') {
                LogParseWarning(pc, "you've used multiple %s directives. Don't do this.",
                           DIRECTIVE_FLAG_CHARS);
            }
        }
        pFlag = strtok_s(NULL, delims, &(pc->strtokContext));

        if (pFlag == NULL) {
            LogParseError(pc, "at least one %s value is missing.",
                       DIRECTIVE_FLAG_CHARS);
            break;
        }


        // validate the value
        if (pFlag != NULL) {
            if ( strchr("%@*_^!~#", *pFlag) != NULL &&  // one of the legal flagchars
                 (i == 0 || *(flagChars[0]) != *pFlag)) // not previously used
                *(flagChars[i]) = pFlag[0];
            else {
                *(flagChars[i]) = defaultValues[i];
                LogParseError(pc, "illegal or duplicate flag (%c) - legal values are [%% @ ! ~ * _ ^]",
                                         pFlag[0]);
            }
        }
        else *(flagChars[i]) = defaultValues[i];
    }
}



void ParseDirective_StatusInquiry(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char *pArg0 = strtok_s(NULL, delims, &(pc->strtokContext));
    char *pArg1 = strtok_s(NULL, delims, &(pc->strtokContext));
    char *pArg2 = strtok_s(NULL, delims, &(pc->strtokContext));

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s %s %s",
               pc->currentIni->Name, pc->currentIni->lineNum,
               pc->p2,
               (pArg0)? pArg0 : "(--)",
               (pArg1)? pArg1 : "(--)",
               (pArg2)? pArg2 : "(--)" );


    if (tc->StatusUrl_IsSpecified) {
        LogParseWarning(pc, "multiple %s directives. Don't do this.",
                   pc->p2);
    }

    tc->StatusUrl_IsSpecified = TRUE;

    if (tc->StatusUrl != NULL && tc->StatusUrl != IIRF_DEFAULT_STATUS_URL_MARKER) {
        free(tc->StatusUrl); // no leak in case of duplicate
        tc->StatusUrl = NULL;
    }

    if (pArg0==NULL) {
        LogParseError(pc, "Did not find any %s Value (OFF|ON)",
                   pc->p2);
    }
    else {
        if (_stricmp(pArg0, "OFF")==0) {
            // do nothing
        }
        else if (!_stricmp(pArg0, "ON")==0) {
            LogParseError(pc, "Did not find a valid %s Value (OFF|ON)",
                       pc->p2);
        }
        else {
            // StatusInquiry is ON....
            if (pArg1!=NULL) {

                // there is a first argument

                if ((pArg2==NULL) &&
                    (_stricmp(pArg1,IIRF_REMOTE_OK_KEYWORD)==0)) {
                    // the RemoteOk keyword is the first arg, and there is no 2nd arg
                    tc->AllowRemoteStatus= TRUE;

                    // Use a well-known value to indicate that we want
                    // the default status URL.  The actual value will be
                    // completed after the ini file has been read
                    // completely, in
                    // SetDefaultVdirConfigValuesAsNecessary().
                    tc->StatusUrl= IIRF_DEFAULT_STATUS_URL_MARKER;
                }

                else {
                    // either there is a second argument, or the RemoteOk
                    // keyword is not the first arg
                    tc->StatusUrl= (char*) malloc(strlen(pArg1)+1);
                    strcpy_s(tc->StatusUrl, strlen(pArg1)+1, pArg1);

                    // if (tc->StatusUrl[0]!='/') {
                    //     LogMessage(tc, 1, "ReadVdirConfig: %s(%d): WARNING: url-path should begin with a slash (/).",
                    //                pc->currentIni->Name,
                    //                pc->currentIni->lineNum);
                    //     tc->nWarnings++;
                    // }

                    if ((pArg2!=NULL) &&
                        (_stricmp(pArg2,IIRF_REMOTE_OK_KEYWORD)==0))
                        tc->AllowRemoteStatus= TRUE;
                }
            }
            else {
                // There is no url-path argument at all.
                // Use a well-known value to indicate that we want the
                // default status URL.  The actual value will be
                // completed after the ini file has been read
                // completely, in SetDefaultVdirConfigValuesAsNecessary().
                tc->StatusUrl= IIRF_DEFAULT_STATUS_URL_MARKER;
            }
        }
    }

    if (tc->StatusUrl != NULL)
        LogMessage(tc, 1, "ReadVdirConfig: %s(%d): IIRF Status Inquiry is enabled at path '%s' for %s.",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum,
                   (tc->StatusUrl == IIRF_DEFAULT_STATUS_URL_MARKER) ? IIRF_DEFAULT_STATUS_URL : tc->StatusUrl,
                   (tc->AllowRemoteStatus==TRUE)
                   ? "local or remote requests"
                   : "local requests only" );
    else
        LogMessage(tc, 1, "ReadVdirConfig: %s(%d): IIRF Status Inquiry is disabled.",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum);
}



void ParseDirective_StatusUrl(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char *pArg1 = strtok_s(NULL, delims, &(pc->strtokContext));
    char *pArg2 = strtok_s(NULL, delims, &(pc->strtokContext));

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s %s %s",
               pc->currentIni->Name, pc->currentIni->lineNum,
               pc->p2,
               (pArg1)? pArg1 : "(--)",
               (pArg2)? pArg2 : "(--)" );

    LogParseWarning(pc, "the %s directive is obsolete. Please use %s.",
               DIRECTIVE_STATUS_URL,
               DIRECTIVE_STATUS_INQUIRY);

    if (tc->StatusUrl_IsSpecified) {
        LogParseWarning(pc, "multiple %s directives. Don't do this.",
                   pc->p2);
    }

    tc->StatusUrl_IsSpecified = TRUE;

    if (tc->StatusUrl != NULL) {
        free(tc->StatusUrl); // no leak in case of duplicate
        tc->StatusUrl = NULL;
    }

    // StatusInquiry is ON....
    if (pArg1!=NULL) {
        // there is a first argument

        if ((pArg2==NULL) &&
            (_stricmp(pArg1,IIRF_REMOTE_OK_KEYWORD)==0)) {
            // the RemoteOk keyword is the first arg, and there is no 2nd arg
            tc->AllowRemoteStatus= TRUE;
            tc->StatusUrl= (char *) _strdup(IIRF_DEFAULT_STATUS_URL);
        }

        else {
            // either there is a second argument, or the RemoteOk
            // keyword is not the first arg
            tc->StatusUrl= (char*) malloc(strlen(pArg1)+1);
            strcpy_s(tc->StatusUrl, strlen(pArg1)+1, pArg1);

            if (tc->StatusUrl[0]!='/') {
                LogParseWarning(pc, "url-path should begin with a slash (/).");
            }

            if ((pArg2!=NULL) &&
                (_stricmp(pArg2,IIRF_REMOTE_OK_KEYWORD)==0))
                tc->AllowRemoteStatus= TRUE;
        }
    }
    else {
        // there is no url-path argument at all
        tc->StatusUrl= (char *) _strdup(IIRF_DEFAULT_STATUS_URL);
    }


    if (tc->StatusUrl != NULL)
        LogMessage(tc, 1, "ReadVdirConfig: %s(%d): IIRF Status Inquiry is enabled at path '%s' for %s.",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum,
                   tc->StatusUrl,
                   (tc->AllowRemoteStatus==TRUE)
                   ? "local or remote requests"
                   : "local requests only" );
    else
        LogMessage(tc, 1, "ReadVdirConfig: %s(%d): IIRF Status Inquiry is disabled.",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum);
}



boolean HandleVdirOnOffSetting(ParseContext *pc,
                               const char *directiveName,
                               boolean isSpecified,
                               boolean defaultValue,
                               char **altString)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char *pSetting = strtok_s(NULL, delims, &(pc->strtokContext));
    boolean setting = FALSE;

    if (isSpecified == TRUE) {
        LogParseWarning(pc, "multiple %s directives. Don't do this.",
                   directiveName);
    }

    if (pSetting!=NULL) {
        if (_stricmp(pSetting, "ON")==0)
            setting= TRUE;
        else if (_stricmp(pSetting, "OFF")==0)
            setting= FALSE;
        else {
            if (altString!=NULL) {
                (*altString) = pSetting;
                return FALSE;
            }
            LogParseError(pc, "Did not find a valid %s Value (OFF|ON)",
                          directiveName);
            setting= defaultValue;
        }
    }
    else {
        LogParseError(pc, "Did not find any %s Value (OFF|ON)",
                      directiveName);
        setting= defaultValue;
    }

    LogMessage(tc, 1, "ReadVdirConfig: %s(%d): %s will be %s.",
               pc->currentIni->Name,
               pc->currentIni->lineNum,
               directiveName,
               (setting)? "enabled" : "disabled"
        );

    return setting;
}




void ParseDirective_RewriteBase(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    char * alt = NULL;

    // coerce the boolean setting to be a pointer value
    tc->RewriteBase = (char*) HandleVdirOnOffSetting(pc, "RewriteBase", tc->RewriteBase_IsSpecified, REWRITE_BASE_DEFAULT, &alt);

    // If the return value from HandleVdirOnOffSetting was FALSE, it
    // indicates the setting was OFF.  FALSE, when is assigned to
    // RewriteBase (a pointer) will be interpreted as NULL. This is what
    // we want when the base is OFF.
    //
    // But! if there's an alternate path explicitly specified in the
    // config file, then RewriteBase gets that value.  If there's no
    // alternate value, but the returned value was TRUE (which evaluates
    // to a pointer of 0x00000001), then RewriteBase gets the implicit
    // vdir path for the current vdir.

    if (alt!=NULL) {
        tc->RewriteBase = _strdup(alt);
    }
    else if (tc->RewriteBase == (far char*)0x00000001) {
        tc->RewriteBase = _strdup(tc->Vdir);
    }

    if (tc->RewriteBase) {
        LogMessage(tc, 1, "ReadVdirConfig: %s(%d): RewriteBase will be '%s'",
                   pc->currentIni->Name,
                   pc->currentIni->lineNum,
                   tc->RewriteBase);
    }

    tc->RewriteBase_IsSpecified = TRUE;
}


void ParseDirective_RewriteEngine(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    tc->EngineOn = HandleVdirOnOffSetting(pc,
                                          "RewriteEngine",
                                          tc->EngineOn_IsSpecified,
                                          ENGINE_ON_DEFAULT,
                                          NULL);
    tc->EngineOn_IsSpecified = TRUE;
}


void ParseDirective_ProxyPreserveHost(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    tc->ProxyPreserveHost = HandleVdirOnOffSetting(pc,
                                                   "ProxyPreserveHost",
                                                   tc->ProxyPreserveHost_IsSpecified,
                                                   FALSE,
                                                   NULL);
    tc->EngineOn_IsSpecified = TRUE;
}


void ParseDirective_UrlDecoding(ParseContext *pc)
{
    IirfVdirConfig * tc = pc->thisConfig;
    tc->UrlDecoding = HandleVdirOnOffSetting(pc,
                                             "UrlDecoding",
                                             tc->UrlDecoding_IsSpecified,
                                             URL_DECODING_DEFAULT,
                                             NULL);
    tc->UrlDecoding_IsSpecified = TRUE;
}



void ParseDirective_RewriteCond(ParseContext *pc)
{
    char *pTestString = strtok_s(NULL, delims, &(pc->strtokContext));
    char *pPattern = strtok_s(NULL, delims, &(pc->strtokContext));
    char *pModifiers = strtok_s(NULL, delims, &(pc->strtokContext));
    RewriteCondition * newCond= NULL;
    int PcreOptions= 0;

    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): RewriteCond   %s  %s '%s'",
               pc->currentIni->Name,
               pc->currentIni->lineNum, pTestString, pPattern, pModifiers );

    // check for bad format
    if ((pTestString == NULL) || (pPattern==NULL)) {
        LogParseError(pc, "bad cond format. Ignoring that Condition!");
        return;
    }

    newCond= (RewriteCondition *) malloc(sizeof(RewriteCondition));
    newCond->Child= NULL;
    newCond->RE= NULL;
    newCond->LogicalOperator=0;
    newCond->SpecialConditionType= '\0';  // null character implies "no special condition"
    newCond->IsNegated=FALSE;

    newCond->TestString= _strdup(pTestString);
    newCond->Pattern= _strdup(pPattern);

    ParseCondModifierFlags(pc->thisConfig, pModifiers, newCond);

    if (newCond->IsCaseInsensitive) PcreOptions |= PCRE_CASELESS;

    // workitem 25269
    if (*pPattern=='!') {
        pPattern++;
        newCond->IsNegated = TRUE;
    }

    HandleSpecialConditionVariant(pPattern, newCond);

    if (newCond->SpecialConditionType == '\0') {
        int errorOffset;
        const char *error;

        // pPattern does not hold a special condition (eg -f/d/s), so process the regular expression.

        newCond->RE= pcre_compile(pPattern,     // the pattern
                                  PcreOptions,  // the options to use when compiling the regex
                                  &error,       // for error message
                                  &errorOffset, // for error offset
                                  NULL);        // use default character tables

        if (newCond->RE == NULL) {
            LogParseError(pc, "compilation of RewriteCond expression '%s' failed at offset %d: %s",
                                     pPattern, errorOffset, error);
            FreeCondList(newCond);
            newCond = NULL;
        }
    }

    if ((newCond != NULL) && ((newCond->RE!= NULL) || (newCond->SpecialConditionType != '\0') ) )
        InsertCond(&(pc->currentCond), newCond);
}





void ParseDirective_IncludeIni(ParseContext *pc, size_t lineLength)
{
    char *pIniFileName = pc->p2 + strlen(pc->p2) +1 ;
    int n = Iirf_ConvertSizeTo32bits(strlen(pIniFileName));
    char *p3= pIniFileName;
    char *p4= pIniFileName + n - 1;
    char * tstr1= NULL;
    char * tstr2= NULL;
    IniFileItem * item = NULL;

    // strip leading and trailing whitespace.
    while((*p3 == ' ')||(*p3 == '\t')) p3++;       // skip leading spaces and TABs
    while((*p4 == ' ')||(*p4 == '\n')||(*p4 == '\r')||(*p4 == '\t')) *p4--='\0'; // trim trailing spaces

    pIniFileName = p3;

    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: %s(%d): IncludeIni '%s'",
               pc->currentIni->Name,
               pc->currentIni->lineNum, pIniFileName);

    if (lineLength <= strlen(pc->p2)) {
        LogParseError(pc,"no ini file specified");
        return;
    }

    if (pIniFileName==NULL) {
        LogParseError(pc,"bad ini filename format");
        return;
    }

    if (*pIniFileName=='\0') {
        LogParseError(pc,"you did not specify an ini file name");
        return;
    }

    tstr1 = (char *) malloc(MAX_PATH*2);
    tstr2 = (char *) malloc(MAX_PATH);

    // Allow relative paths.
    // This bunch of code appends 2 paths together and normalizes them.
    // If the ini filename is an absolute or relative path, this
    // results in the correct normalized path being used.
    strcpy_s(tstr1, MAX_PATH*2, pc->currentIni->Name);
    PathRemoveFileSpec(tstr1);
    PathAppend(tstr1, pIniFileName);
    PathSearchAndQualify (tstr1, tstr2, MAX_PATH); // result goes into tstr2
    free(tstr1);

    item = (IniFileItem *) malloc(sizeof(IniFileItem));
    item->Name       = tstr2;  // must free later in FreeIniFileChain()
    item->lineNum    = 0;
    item->isMap      = FALSE;
    item->parent     = NULL;
    item->firstChild = NULL;
    item->sibling    = NULL;
    n= fopen_s(&(item->file), item->Name, "r");

    if (n != 0) {
        int e = n; // GetLastError();
        char eMsg[256];
        Iirf_GenErrorMessage(e, eMsg, 256);
        // this doesn't warrant an event log event
        LogMessage(pc->thisConfig, 1, "ReadVdirConfig: Could not open included ini file '%s' (error: %d, %s)",
                   item->Name, e, eMsg);
        free(item);
        free(tstr2);
        return;
    }

    // Append this ini to the linked list of files to check
    // for update, for each request.
    InsertIniItem(pc, item);

    pc->currentIni = item;

    LogMessage(pc->thisConfig, 1, "---------------------------------");
    LogMessage(pc->thisConfig, 1, "ReadVdirConfig: reading included ini file: %s", item->Name);
}




void FreeIniFileChain(IniFileItem *root)
{
    IniFileItem * p = root;
    while (p!=NULL) {
        IniFileItem * child = p->firstChild;
        free(p->Name);
        FreeIniFileChain(p->sibling);
        free(p);
        p = child;
    }
}


void FreeStatusMsgChain(ArchivedStatusMessage *root)
{
    ArchivedStatusMessage * p = root;
    while (p!=NULL) {
        ArchivedStatusMessage *next = p->Next;
        free(p->Text);
        free(p);
        p = next;
    }
}


void CountIniLines(IirfVdirConfig *tc, IniFileItem *root, int *nLines, int *nFiles)
{
    IniFileItem *item = root;

    while (item != NULL) {
        if (!item->isMap) {
            LogMessage(tc, 3, "CountIniLines: ini file %s (%d lines)",
                       item->Name, item->lineNum);
            (*nFiles)++;
            (*nLines) += item->lineNum;
        }
        CountIniLines(tc, item->sibling, nLines, nFiles);
        item = item->firstChild;
    }
}


void SetDefaultVdirConfigValuesAsNecessary(IirfVdirConfig *tc, boolean foundIniFile)
{
    int i;
    // set the defaults as necessary
    if (tc->CondSubstringBackrefFlag == '\0')
        tc->CondSubstringBackrefFlag= COND_SUBSTRING_BACKREF_FLAG_DEFAULT;

    if (tc->ConversionFlagChar == '\0')
        tc->ConversionFlagChar= CONVERSION_FLAG_DEFAULT;

    if (tc->MaxMatchCount == 0)
        tc->MaxMatchCount= MAX_MATCH_COUNT_DEFAULT;

    if (tc->IterationLimit==0)
        tc->IterationLimit= ITERATION_LIMIT_DEFAULT;

    if (tc->LogLevel== -1)
        tc->LogLevel= LOG_LEVEL_DEFAULT;

    if (tc->UrlDecoding_IsSpecified == FALSE)
        tc->UrlDecoding = URL_DECODING_DEFAULT;

    if (tc->RewriteBase_IsSpecified == FALSE)
        tc->RewriteBase = REWRITE_BASE_DEFAULT;

    // set the statusUrl appropriately
    if (!foundIniFile) {
        // there was no ini file - enable it at the default location
        tc->StatusUrl= Iirf_AllocAndConcatenate(tc->Vdir, IIRF_DEFAULT_STATUS_URL);
    }
    else if (tc->StatusUrl == IIRF_DEFAULT_STATUS_URL_MARKER) {
        // want the default status URL.
        // In this case, just use the appropriate URL, whether or not
        // RewriteBase is on.
        if (tc->Vdir[0]=='/' && tc->Vdir[1]=='\0')
            tc->StatusUrl= (char *) _strdup(IIRF_DEFAULT_STATUS_URL);
        else
            tc->StatusUrl= Iirf_AllocAndConcatenate(tc->Vdir, IIRF_DEFAULT_STATUS_URL);

    } else if (tc->StatusUrl != NULL) {
        // The ini file has specified a status url, explicitly (against recommendations!)
        // Apply the base URL, if RewriteBase is enabled. But check for double-slash.
        if (tc->RewriteBase && tc->RewriteBase[0]!='\0') {
            // do not double slash
            int delta = (((tc->RewriteBase[0]=='/' && tc->RewriteBase[1]=='\0') ||
                          tc->RewriteBase[strlen(tc->RewriteBase)-1]=='/')
                         && tc->StatusUrl[0]=='/')
                ? 1 : 0;

            char * orig = tc->StatusUrl;
            tc->StatusUrl= Iirf_AllocAndConcatenate(tc->RewriteBase, tc->StatusUrl+delta);
            free(orig);
        }
    }

    if (tc->EngineOn_IsSpecified == FALSE)
        tc->EngineOn = ENGINE_ON_DEFAULT;

    if (tc->ProxyPreserveHost_IsSpecified == FALSE)
        tc->ProxyPreserveHost = FALSE;
    else if (tc->ProxyPreserveHost == TRUE) {
        // force all ProxyPass to preserve the original host
        RewriteRule * rule = tc->rootRule;
        int numFound = 0;
        while (rule!=NULL) {
            if (rule->RuleFlavor == FLAVOR_PROXY) {
                numFound++;
                rule->ProxyPreserveHost = TRUE;
            }
            rule = rule->next;
        }
        // sanity advisement
        if (numFound == 0)
            LogMessage(tc, 1, "ReadVdirConfig: INFO: ProxyPreserveHost is in use, but no ProxyPass rules were found.");
    }

    for (i=0; i < 4;  i++) {
        if (tc->ProxyTimeout[i] < 0)
            tc->ProxyTimeout[i] = HTTP_TIMEOUT_DEFAULT;
    }

    // workitem 26720: check for use of U modifier, and NotifyLog directive
    {
        RewriteRule * r = tc->rootRule;
        boolean unmangle = FALSE;
        while (r!=NULL) {
            if (r->RecordOriginalUrl) unmangle = TRUE;
            r= r->next;
        }
        if (unmangle) {
            if (gFilterConfig->WantNotifyLog) {
                LogMessage(tc, 1, "ReadVdirConfig: INFO: [U] flag in use, with global NotifyLog - Unmangled URIs will be logged.");
            }
            else {
                LogMessage(tc, 1, "ReadVdirConfig: INFO: No global NotifyLog - Unmangled URIs will not be logged.");
            }
        }
    }
}



IirfVdirConfig * ReadVdirConfig(char *configFile, char *applMdPath, IirfVdirConfig *oldCfg)
{
    ParseContext *pc = (ParseContext *) malloc(sizeof(ParseContext));
    size_t lineLength, L2;
    int pass, n;
    unsigned char *p1, *buffer = (unsigned char *) malloc(MAX_LINE_LENGTH);
    IirfVdirConfig *tc = NULL;
    IniFileItem *item = NULL;

    TRACE("ReadVdirConfig: (configFile='%s', applMdPath='%s', oldCfg= 0x%08X)", configFile, applMdPath, oldCfg );

    if (buffer==NULL) {
        if (pc) free(pc);
        return NULL;
    }
    if (pc==NULL) {
        if (buffer) free(buffer);
        return NULL;
    }

    pc->thisConfig    = NewVdirConfig(configFile, applMdPath);
    pc->currentRule   = NULL;
    pc->previousRule  = NULL;
    pc->currentCond   = NULL;
    pc->strtokContext = NULL;
    pc->currentIni    = pc->thisConfig->IniChain;

    tc = pc->thisConfig;

    // this appears in output only in testing, as the logfile is not yet set.
    LogMessage(tc, 1, "ReadVdirConfig");

    GetSystemTime(&(tc->ConfigRead));

    // Read the config file in 3 passes: first to get the loglevel, then
    // the logfile, and finally to get the rest of the settings.  We
    // need the the logfilename before all the other directives, so we
    // can log effectively. But we need the loglevel before the logfile,
    // for similar reasons: the greeting log string is emitted when
    // parsing the LogFile directive, and if the loglevel is not set by
    // then, you get nothing.  Therefore we need 3 total passes: #1 for
    // loglevel, #2 for logfile, then #3 for all other directives.

    for (pass=0; pass < 3; pass++ ) {
        LogMessage(tc, 4, "ReadVdirConfig: pass %d", pass);
        n= fopen_s(&(pc->currentIni->file), configFile, "rt");

        if (n != 0) {
            // cannot read ini file. could be ENOFILE, EACCESS, etc
            TCHAR eMsg[256];
            int e = n; // GetLastError();
            const char * eventMsgFormat = "IIRF: Could not open ini file '%s' (error: %d, %s)";
            Iirf_GenErrorMessage(e, eMsg, 256);
            // workitem 29890
            if (pass!=0) {
                // If this is not the 1st pass, something odd happened.
                // It's possible we have the log file, so try logging a message.
                LogMessage(tc, 1, "ReadVdirConfig: Could not open ini file '%s' on pass %d (error: %d, %s)",
                           configFile, pass, e, eMsg);
            }
            else {
                int len = _scprintf( eventMsgFormat, configFile, e, eMsg) + 1;
                char * msg = (char*) malloc( len * sizeof(char) );
                sprintf_s(msg, len, eventMsgFormat, configFile, e, eMsg);
                InsertIirfStatusMsg(tc, msg, 2);
                // do not free msg; it gets freed later.
            }

            // workitem 30216
            if (gFilterConfig->WantEventsForIniOpen &&
                !AlreadyLoggedIniOpenFailure(configFile)) {
                Iirf_EmitEventLogEventX(EVENTLOG_WARNING_TYPE,
                                        IIRF_EVENT_CANNOT_READ_INI,
                                        NULL,
                                        eventMsgFormat, configFile, e, eMsg);

                RememberIniOpenFailure(configFile);
            }

            free(buffer);
            free(pc);

            // we cannot read the ini file; set the default values.
            SetDefaultVdirConfigValuesAsNecessary(tc, FALSE);

            return tc;  // a bunch of default settings
        }
        else if (pass==0)
            ForgetIniOpenFailure(configFile);


        pc->currentIni->lineNum = 0;
        while (TRUE) {
            pc->currentIni->lineNum++;
            if (fgets((char *)buffer, MAX_LINE_LENGTH, pc->currentIni->file) == NULL) {
                // done reading this ini file
                fclose(pc->currentIni->file);
                pc->currentIni->file = NULL;
                // is this the "root' ini file?
                if (pc->currentIni->parent == NULL) break;  // all done
                else {
                    // We're in an included file.
                    // Walk up the chain, and continue reading.
                    LogMessage(pc->thisConfig, 1, "---------------------------------");
                    pc->currentIni = pc->currentIni->parent;
                    continue;
                }
            }

            p1 = buffer;
            while (isspace(*p1)) p1++;
            if (*p1 == 0) continue;    // empty line

            if (*p1 == '#') continue;  // comment

            // WorkItemId 9856
            lineLength= strlen(p1);
            pc->p2= strtok_s(p1, " \t\n", &(pc->strtokContext));  // split by spaces or TAB

            if (pc->p2 != NULL)
            {
                // chop
                L2 = strlen(pc->p2);
                while (pc->p2[L2-1] == '\n' || pc->p2[L2-1] == '\r')
                    pc->p2[--L2] = '\0';
            }

            if (pass==0) {
                // first pass, parse only the loglevel directives
                if (_stricmp(pc->p2, DIRECTIVE_REWRITE_LOG_LEVEL)==0)
                    ParseDirective_LogLevel(pc);
            }
            else if (pass==1) {
                // Must match on RewriteLogLevel *first*, before RewriteLog, because, using strnicmp,
                // the former will match the latter.
                if (_stricmp(pc->p2, DIRECTIVE_REWRITE_LOG_LEVEL)==0) {}
                else if (_stricmp(pc->p2,DIRECTIVE_REWRITE_LOG_FILE)==0)
                    ParseDirective_LogFile(pc, lineLength);
            }
            else {
                // pass 2
                if (_stricmp(pc->p2, DIRECTIVE_PROXY_PASS_REVERSE)==0)
                    ParseDirective_ProxyPassReverse(pc);

                else if ((_stricmp(pc->p2, DIRECTIVE_REWRITE_RULE)==0) ||
                    (_stricmp(pc->p2, DIRECTIVE_REDIRECT_RULE)==0) ||
                    (_stricmp(pc->p2, DIRECTIVE_REWRITE_HEADER)==0) ||
                    (_stricmp(pc->p2, DIRECTIVE_PROXY_PASS)==0)) {

                    ParseDirective_RewriteRule(pc);
                }

                else if (_stricmp(pc->p2, DIRECTIVE_REWRITE_COND)==0)
                    ParseDirective_RewriteCond(pc);

                else if (_stricmp(pc->p2, DIRECTIVE_REWRITE_BASE)==0)
                    ParseDirective_RewriteBase(pc);

                else if (_stricmp(pc->p2, DIRECTIVE_REWRITE_MAP)==0)
                    ParseDirective_RewriteMap(pc);

                else if (_stricmp(pc->p2, DIRECTIVE_INCLUDE)==0)
                    ParseDirective_IncludeIni(pc, lineLength);

                else if (_stricmp(pc->p2, DIRECTIVE_URL_DECODING)==0)
                    ParseDirective_UrlDecoding(pc);

                else if (_stricmp(pc->p2,DIRECTIVE_ITERATION_LIMIT)==0)
                    ParseDirective_IterationLimit(pc);

                else if (_stricmp(pc->p2,DIRECTIVE_MAX_MATCH_COUNT)==0)
                    ParseDirective_MaxMatchCount(pc);

                // workitem 25951
                else if (_stricmp(pc->p2, DIRECTIVE_PROXY_TIMEOUTS)==0)
                    ParseDirective_ProxyTimeouts(pc, p1, lineLength);

                // workitem 30847
                else if (_stricmp(pc->p2,DIRECTIVE_FLAG_CHARS)==0)
                    ParseDirective_FlagCharacters(pc);

                // workitem 17024
                else if (_stricmp(pc->p2,DIRECTIVE_COND_SUBSTRING_FLAG)==0)
                    ParseDirective_CondSubstringFlag(pc);

                // workitem 23459
                else if (_stricmp(pc->p2,DIRECTIVE_STATUS_INQUIRY)==0)
                    ParseDirective_StatusInquiry(pc);

                // this is supported for backwards compatibility only
                else if (_stricmp(pc->p2,DIRECTIVE_STATUS_URL)==0)
                    ParseDirective_StatusUrl(pc);

                // workitem 23458
                else if (_stricmp(pc->p2, DIRECTIVE_REWRITE_ENGINE)==0)
                    ParseDirective_RewriteEngine(pc);

                // workitem 29415
                else if (_stricmp(pc->p2, DIRECTIVE_PROXY_PRESERVE_HOST)==0)
                    ParseDirective_ProxyPreserveHost(pc);

                else if (_stricmp(pc->p2,DIRECTIVE_REWRITE_LOG_LEVEL)==0) {
                    // ignore - handled in pass 0
                }
                else if (_stricmp(pc->p2,DIRECTIVE_REWRITE_LOG_FILE)==0) {
                    // ignore - handled in pass 1
                }

                else {
                    LogParseWarning(pc, "unrecognized directive, ignoring it: '%s'",
                                    pc->p2);
                }
            }
        }
    }

    free(buffer);

    if (pc->currentCond!=NULL) {
        LogParseWarning(pc, "Dangling %s found in ini file",
                   DIRECTIVE_REWRITE_COND);
        FreeCondList(pc->currentCond);
    }

    SetDefaultVdirConfigValuesAsNecessary(tc, TRUE);

    // walk the list to total up all lines of ini
    tc->nFiles = 0;
    CountIniLines(tc, tc->IniChain, &(tc->nLines), &(tc->nFiles));

    if (tc->Vdir[0]=='\0')
        LogMessage(tc, 1, "ReadVdirConfig: Done reading INI for the root vdir, found %d rules (%d errors, %d warnings) on %d lines, in %d modules",
                   tc->nRules, tc->nErrors, tc->nWarnings, tc->nLines, tc->nFiles);
    else
        LogMessage(tc, 1, "ReadVdirConfig: Done reading INI for vdir(%s), found %d rules (%d errors, %d warnings) on %d lines, in %d modules",
                   tc->Vdir, tc->nRules, tc->nErrors, tc->nWarnings, tc->nLines, tc->nFiles);

    free(pc);
    return tc;
}




IirfVdirConfig * ReadNewVdirConfig(char *applMdPath, char *applPhysicalPath)
{
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    IirfVdirConfig *cfg;
    char iniFileName[_MAX_PATH];

    TRACE("ReadNewVdirConfig");

    _splitpath_s(applPhysicalPath, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
    _makepath_s(iniFileName, _MAX_PATH, drive, dir, "Iirf", ".ini");

    cfg = ReadVdirConfig(iniFileName, applMdPath, NULL);
    return cfg;
}






void ReleaseOrExpireVdirConfig (IirfVdirConfig *config, int operation)
{
    CRITICAL_SECTION *pCS;
    boolean destroyed = FALSE;

    if (config==NULL) return;

    TRACE("ReleaseOrExpireVdirConfig: cfg=0x%08X  op=%d", config, operation);

    EnterCriticalSection(config->pCS);
    pCS = config->pCS;

    if (operation==0)
        config->RefCount--;
    else
        config->Expired = TRUE;

    LogMessage( config, 4, "ReleaseOrExpireVdirConfig: vdir '%s' (era=%d) (rc=%d) (Expired=%d) (ptr=0x%08X)...",
                config->ApplMdPath,
                config->Era,
                config->RefCount,
                config->Expired,
                config);

    if ((config->RefCount<= 0) && (config->Expired)) {
        destroyed = TRUE;
        if (config->rootRule)     FreeRuleList(config->rootRule);
        FreeIniFileChain(config->IniChain);
        FreeStatusMsgChain(config->statusMsgs);
        if (config->LogFileName)  free(config->LogFileName);
        if (config->ApplMdPath)   free(config->ApplMdPath);
        if (config->RewriteBase)  free(config->RewriteBase);
        if (config->StatusUrl)    free(config->StatusUrl);
        if (config->rootMap)      FreeRewriteMap(config, config->rootMap);
        if (config->rootPpr)      FreeProxyPassReverse(config, config->rootPpr);
        ReleaseLogFile(config->pLogFile);

        EnterCriticalSection(&gcsVdirConfig);
        if (gVdirConfigList == config)
            gVdirConfigList = NULL;
        else {
            // remove that element from the linked list
            IirfVdirConfig *current = gVdirConfigList;
            while (current && current->Next != config) current = current->Next;
            if (current && current->Next)
                current->Next = config->Next;
        }
        LeaveCriticalSection(&gcsVdirConfig);

        free(config); // gone
    }

    LeaveCriticalSection(pCS);
    if (destroyed) {
        DeleteCriticalSection(pCS);
        free(pCS);
    }

    return;
}


void ExpireVdirConfig (IirfVdirConfig *config)
{
    ReleaseOrExpireVdirConfig (config, 1) ;
}

void ReleaseVdirConfig (IirfVdirConfig *config)
{
    ReleaseOrExpireVdirConfig (config, 0) ;
}




IirfVdirConfig * GetVdirConfig(char *applMdPath, char *applPhysicalPath)
{
    IirfVdirConfig *current, *previous;

    TRACE("GetVdirConfig");
    // Protect potential updates to the list with the critical section.
    // We just use one coarse-grained lock.  We *could* optimize to use a
    // reader-writer lock with upgrades, but that is for another day.
    EnterCriticalSection(&gcsVdirConfig);
    current = gVdirConfigList;

    // walk the list
    while (current != NULL) {
        if (strcmp(current->ApplMdPath, applMdPath)==0) {
            // found a match
            if (IsIniChainUpdated(current, current->IniChain)) {
                // an ini file has been updated, must re-read
                IirfVdirConfig *newCfg;

                LogMessage( current, 4, "GetVdirConfig: Obtain  vdir '%s' , Ini file has been updated.",
                            current->ApplMdPath);

                // Need to re-read the configuration for this applMdPath.

                newCfg = ReadVdirConfig(current->IniChain->Name, current->ApplMdPath, current) ;
                newCfg->RefCount = 1;
                // Era is used for for diagnostic purposes only.
                // It indicates how many times the ini has been updated.
                newCfg->Era = current->Era+1;

                newCfg->Next = current->Next;
                if (current == gVdirConfigList)
                    gVdirConfigList = newCfg;
                else
                    // append to the linked list
                    previous->Next = newCfg;

                // done using this config; decrement the refcount and expire it.
                ExpireVdirConfig(current);

                current = newCfg;
            }
            else {
                EnterCriticalSection(current->pCS);
                current->RefCount++;
                LeaveCriticalSection(current->pCS);
            }

            LeaveCriticalSection(&gcsVdirConfig);
            LogMessage( current, 4, "GetVdirConfig: Obtain  vdir '%s' (era=%d) (rc=%d) (Expired=%d) (ptr=0x%08X)...",
                        current->ApplMdPath,
                        current->Era,
                        current->RefCount,
                        current->Expired,
                        current);
            return current;
        }
        previous = current;
        current = current->Next;
    }

    // Arriving here means there is no config available for the given
    // applMdPath.
    // So we read the configuration in, and insert it into the list.

    current = ReadNewVdirConfig(applMdPath, applPhysicalPath);
    if (gVdirConfigList == NULL)
        gVdirConfigList = current;
    else {
        // append to the linked list
        previous->Next = current;
    }

    LeaveCriticalSection(&gcsVdirConfig);

    LogMessage( current, 4, "GetVdirConfig: Obtain  vdir '%s' (era=%d) (rc=%d) (Expired=%d) (ptr=0x%08X)...",
                current->ApplMdPath,
                current->Era,
                current->RefCount,
                current->Expired,
                current);

    return current;
}




IirfVdirConfig * GetVdirConfigFromServerVars(HTTP_FILTER_CONTEXT * pfc)
{
    char * applMdPath = GetServerVariable_AutoFree(pfc, "APPL_MD_PATH");
    char * applPhysicalPath = GetServerVariable_AutoFree(pfc, "APPL_PHYSICAL_PATH");
    IirfRequestContext *ctx = (IirfRequestContext *) pfc->pFilterContext;
    IirfVdirConfig * vdirConfig = GetVdirConfig(applMdPath, applPhysicalPath);
    ctx->VdirConfig = vdirConfig;
    return vdirConfig;
}




IirfVdirConfig * GetVdirConfigFromFilterContext(HTTP_FILTER_CONTEXT * pfc)
{
    IirfRequestContext *ctx= (IirfRequestContext *) pfc->pFilterContext;
    TRACE("GetVdirConfigFromFilterContext: cfg=0x%08X", ctx->VdirConfig);
    return ctx->VdirConfig;
}


char * PriorityToString(DWORD FilterPriority)
{
    if (FilterPriority==SF_NOTIFY_ORDER_HIGH) return "HIGH";
    if (FilterPriority==SF_NOTIFY_ORDER_MEDIUM) return "MEDIUM";
    if (FilterPriority==SF_NOTIFY_ORDER_LOW) return "LOW";
    return "Unknown";
}



IirfServerConfig * Iirf_NewServerConfig()
{
    IirfServerConfig * c= (IirfServerConfig *) malloc(sizeof(IirfServerConfig));

    // set defaults:
    c->MsgCache= NULL;
    c->EngineOff= FALSE; // workitem 24380
    c->EngineOff_IsSpecified= FALSE;

    c->FilterPriority= SF_NOTIFY_ORDER_DEFAULT ;

    c->WantNotifyLog= WANT_NOTIFY_LOG_DEFAULT;
    c->WantNotifyLog_IsSpecified= FALSE;

    c->EnableStatusInquiry = ENABLE_STATUS_INQUIRY_DEFAULT;
    c->EnableStatusInquiry_IsSpecified= FALSE;

    c->WantEventsForIniOpen= WANT_INI_EVENTS_DEFAULT;
    c->WantEventsForIniOpen_IsSpecified= FALSE;

    c->Testing = FALSE;
    c->MaxFieldLength= 0; // will get defaulted later
    c->nWarnings= 0;
    c->nLines= 0;

    GetSystemTime(&(c->StartupTime));

    return c;
}



void HandleServerIntegerSetting( IirfServerConfig * thisConfig,
                                 int lineNum,
                                 char *directive,
                                 int *value,
                                 int max,
                                 int min,
                                 char *setting)
{
    if (*value != 0) {
        CacheLogMessage(1, "ReadServerConfig: %s(%d): WARNING: multiple %s directives. Don't do this.",
                        thisConfig->IniFileName,
                        lineNum, directive);
        thisConfig->nWarnings++;
    }

    if (setting!=NULL) {
        *value = atoi(setting);
        if (*value < min || *value > max) {
            CacheLogMessage(1,"ReadServerConfig: %s(%d): WARNING: Did not find a valid %s Value (%d)",
                            thisConfig->IniFileName,
                            lineNum, directive, *value );
            *value = 0; // unset
            thisConfig->nWarnings++;
        }
    }
    else {
        CacheLogMessage(1,"ReadServerConfig: %s(%d): WARNING: Did not find any %s Value",
                        thisConfig->IniFileName,
                        lineNum, directive );
        thisConfig->nWarnings++;
    }

    CacheLogMessage(2,"ReadServerConfig: %s(%d): %s setting is now: %d",
                    thisConfig->IniFileName,
                    lineNum,
                    directive, (*value));
}


void HandleServerOnOffSetting( IirfServerConfig * thisConfig,
                               int lineNum,
                               char *directive,
                               boolean *flag,
                               boolean *flag_IsSpecified,
                               char *setting)
{
    if (*flag_IsSpecified == TRUE) {
        CacheLogMessage(1, "ReadServerConfig: %s(%d): WARNING: multiple %s directives. Don't do this.",
                        thisConfig->IniFileName,
                        lineNum, directive);
        thisConfig->nWarnings++;
    }
    *flag_IsSpecified = TRUE;

    if (setting!=NULL) {
        if (_stricmp(setting, "ON")==0)
            (*flag)= TRUE;
        else if (_stricmp(setting, "OFF")==0)
            (*flag)= FALSE;
        else {
            CacheLogMessage(1,"ReadServerConfig: %s(%d): WARNING: Did not find a valid %s Value (OFF|ON)",
                            thisConfig->IniFileName,
                            lineNum, directive );
            thisConfig->nWarnings++;
        }
    }
    else {
        CacheLogMessage(1,"ReadServerConfig: %s(%d): WARNING: Did not find any %s Value (OFF|ON)",
                        thisConfig->IniFileName,
                        lineNum, directive );
        thisConfig->nWarnings++;
    }

    CacheLogMessage(2,"ReadServerConfig: %s(%d): %s setting is now: %s",
                    thisConfig->IniFileName,
                    lineNum,
                    directive, (*flag) ? "ON" : "OFF");
}


void SetDefaultServerConfigValuesAsNecessary(IirfServerConfig *thisConfig)
{
    if (thisConfig->MaxFieldLength == 0) {
        thisConfig->MaxFieldLength = SERVER_VAR_BUFFER_SIZE_DEFAULT_MAX;
    }
}


// EXPORT - for TestDriver
void Iirf_ReadServerConfig(IirfServerConfig *thisConfig)
{
    unsigned char *buffer = (unsigned char *) malloc(MAX_LINE_LENGTH);
    FILE *infile;
    int e, lineNum;
    char *p1, *p2, *strtokContext= NULL;
    FILETIME lastWrite;
    char delims[] = " \n\r\t";

    if (thisConfig == NULL) return ;
    if (buffer == NULL)  return ;

    TRACE("Iirf_ReadServerConfig: file = (%s)", thisConfig->IniFileName);

    // get time of last write for the ini file we are about to read
    thisConfig->IniLastUpdated = (GetLastUpdate(thisConfig->IniFileName, &lastWrite))
        ? Iirf_FileTimeToLocalTimeString(&lastWrite)
        : NULL;

    e = fopen_s(&infile, thisConfig->IniFileName, "r");
    if (e != 0) {
        CHAR eMsg[256];
        Iirf_GenErrorMessage(e, eMsg, 256);
        // not an error; it's common to have no server-wide config file.
        CacheLogMessage(2, "ReadServerConfig: INFO: Could not open ini file '%s' (error: %d, %s)",
                        thisConfig->IniFileName, e, eMsg);

        if (e == 2) {
            char *msg1 = "-- None, the ini file does not exist. --";
            thisConfig->IniLastUpdated = _strdup(msg1);
        }
        else {
            char *format = "-- None, the ini file could not be opened (error=%d) --";
            int len = _scprintf( format, e ) + 1; // _scprintf doesn't count terminating '\0'
            thisConfig->IniLastUpdated = malloc(len * sizeof(char));
            sprintf_s(thisConfig->IniLastUpdated, len, format, e);
        }
        SetDefaultServerConfigValuesAsNecessary(thisConfig);
        free(buffer);
        return;
    }


    lineNum= 0;
    while (TRUE) {
        lineNum++;
        if (fgets((char *)buffer, MAX_LINE_LENGTH, infile) == NULL) break;

        p1 = buffer;
        while (isspace(*p1)) p1++; // skip spaces
        if (*p1 == 0) continue;    // empty line
        if (*p1 == '#') continue;  // comment

        //lineLength= strlen(p1);
        p2= strtok_s(p1, " \t", &strtokContext);  // split by spaces or TAB

        if (_stricmp(p2,DIRECTIVE_FILTER_PRIORITY)==0) {
            char *pPriority = strtok_s(NULL, delims, &strtokContext);
            if (pPriority!=NULL) {
                if (_stricmp(pPriority, "HIGH")==0)
                    thisConfig->FilterPriority= SF_NOTIFY_ORDER_HIGH ;
                else if (_stricmp(pPriority, "MEDIUM")==0)
                    thisConfig->FilterPriority= SF_NOTIFY_ORDER_MEDIUM ;
                else if (_stricmp(pPriority, "LOW")==0)
                    thisConfig->FilterPriority= SF_NOTIFY_ORDER_LOW ;
                else if (_stricmp(pPriority, "DEFAULT")==0)
                    thisConfig->FilterPriority= SF_NOTIFY_ORDER_DEFAULT ;
                else {
                    CacheLogMessage(2, "ReadServerConfig: %s(%d): WARNING: Did not find valid Filter Priority Value (HIGH|MEDIUM|LOW)", thisConfig->IniFileName, lineNum );
                    thisConfig->nWarnings++;
                }
            }
            else {
                CacheLogMessage(2, "ReadServerConfig: %s(%d): WARNING: Did not find any Filter Priority Value (HIGH|MEDIUM|LOW)", thisConfig->IniFileName, lineNum);
                thisConfig->nWarnings++;
            }

            CacheLogMessage(2, "ReadServerConfig: %s(%d): Filter Priority is now: %s (0x%04x)",
                            thisConfig->IniFileName,
                            lineNum,
                            PriorityToString(thisConfig->FilterPriority),
                            thisConfig->FilterPriority);
        }

        else if (_stricmp(p2,DIRECTIVE_NOTIFY_LOG)==0) {
            char *pSetting = strtok_s(NULL, delims, &strtokContext);
            HandleServerOnOffSetting( thisConfig,
                                      lineNum,
                                      DIRECTIVE_NOTIFY_LOG,
                                      &(thisConfig->WantNotifyLog),
                                      &(thisConfig->WantNotifyLog_IsSpecified),
                                      pSetting);
        }

        else if (_stricmp(p2,DIRECTIVE_MAX_FIELD_LENGTH)==0) {
            char *pSetting = strtok_s(NULL, delims, &strtokContext);
            HandleServerIntegerSetting( thisConfig,
                                        lineNum,
                                        DIRECTIVE_MAX_FIELD_LENGTH,
                                        &(thisConfig->MaxFieldLength),
                                        SERVER_VAR_BUFFER_SIZE_MAX_MAX,
                                        SERVER_VAR_BUFFER_SIZE_MIN_MAX,
                                        pSetting);
        }

        // workitem 30216
        else if (_stricmp(p2,DIRECTIVE_EVENTS_FOR_INI_OPEN)==0) {
            char *pSetting = strtok_s(NULL, delims, &strtokContext);
            HandleServerOnOffSetting( thisConfig,
                                      lineNum,
                                      DIRECTIVE_EVENTS_FOR_INI_OPEN,
                                      &(thisConfig->WantEventsForIniOpen),
                                      &(thisConfig->WantEventsForIniOpen_IsSpecified),
                                      pSetting);
        }

        // workitem 25982
        else if (_stricmp(p2,DIRECTIVE_STATUS_INQUIRY)==0) {
            char *pSetting = strtok_s(NULL, delims, &strtokContext);
            HandleServerOnOffSetting( thisConfig,
                                      lineNum,
                                      DIRECTIVE_STATUS_INQUIRY,
                                      &(thisConfig->EnableStatusInquiry),
                                      &(thisConfig->EnableStatusInquiry_IsSpecified),
                                      pSetting);
        }

        // workitem 23458
        else if (_stricmp(p2,DIRECTIVE_REWRITE_ENGINE)==0) {
            char *pSetting = strtok_s(NULL, delims, &strtokContext);
            boolean flag = FALSE;
            HandleServerOnOffSetting( thisConfig,
                                      lineNum,
                                      DIRECTIVE_REWRITE_ENGINE,
                                      &flag,
                                      &(thisConfig->EngineOff_IsSpecified),
                                      pSetting);
            thisConfig->EngineOff = !flag;
        }

        else {
            CacheLogMessage(2, "ReadServerConfig: %s(%d): WARNING: unrecognized directive, ignoring it: '%s'",
                            thisConfig->IniFileName, lineNum, p2);
            thisConfig->nWarnings++;
        }
    }

    SetDefaultServerConfigValuesAsNecessary(thisConfig);

    thisConfig->nLines = lineNum;

    fclose(infile);
    free(buffer);

    return;
}




// This is used only when the IsapiRewriter is being driven in the test app.
// This is never called from the ISAPI itself.
// extern "C"
IirfVdirConfig * Iirf_IsapiFilterTestSetup(char * psz_iniDirName)
{
    HANDLE hFile;
    char iniFileName[_MAX_PATH];
    IirfVdirConfig *config;

    gFilterConfig= Iirf_NewServerConfig();
    gFilterConfig->Testing= TRUE;

    _makepath_s(iniFileName, _MAX_PATH, NULL, psz_iniDirName, "Iirf", ".ini");

    hFile = CreateFile( iniFileName, // file or directory path
                        GENERIC_READ,
                        FILE_SHARE_READ|FILE_SHARE_DELETE,
                        NULL,
                        OPEN_EXISTING,                      // open but dont create
                        FILE_ATTRIBUTE_NORMAL,
                        NULL
        );

    // If file does not exist, then assume it's a directory.
    // Append IIrf.ini to it, and try opening THAT.
    if (hFile == INVALID_HANDLE_VALUE)
        _makepath_s(iniFileName, _MAX_PATH, NULL, psz_iniDirName, "Iirf", ".ini");


    //_makepath_s(IniFileDirectory, _MAX_PATH, NULL, psz_iniDirName, NULL, NULL);
    //printf("\nnew target ini file: '%s'\n", IniFileName);

    //     sprintf(t, "%s\\%s", psz_iniDirName, IniFileName);
    //     strncpy(IniFileName, t, _MAX_PATH);
    //     strncpy(IniFileDirectory, psz_iniDirName, _MAX_PATH);

    //strncpy(IniFileName, psz_iniFileName, _MAX_PATH);
    //GetCurrentDirectory(sizeof(IniFileDirectory)/sizeof(IniFileDirectory[0]),
    //IniFileDirectory);

    printf("Trying to read config at '%s'\n", iniFileName);
    config= ReadVdirConfig(iniFileName,"None", NULL);
    printf("done reading new config\n");
    if (config == NULL) {
        printf("no config.  Exiting.\n");
        exit(1);
    }
    return config;
}

