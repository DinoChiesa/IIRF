/*

  IirfConfig.h

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2010.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  or, see Rewriter.c for the details of the license.

  Last saved:
  Time-stamp: <2011-October-02 16:55:39>

*/


#ifndef IIRF_CONFIG_H
#define IIRF_CONFIG_H

#include <WTypes.h>  // CRITICAL_SECTION
#include <stdio.h>   // FILE

#include "RewriteRule.h"


typedef struct _LogFileEntry {
    int RefCount;
    FILE *LogFile;
    char *LogFileName;
    CRITICAL_SECTION *pCS;       // serialize usage of this logfile
    struct _LogFileEntry * Next; // linked list
} LogFileEntry;


typedef struct _IniFileItem {
    FILE * file;
    char * Name;
    int lineNum;
    boolean isMap; // for bookkeeping purposes, see CountIniLines()
    FILETIME LastWrite;

    // Ini files form a doubly-linked list (parent-to-child), but also,
    // each child may have siblings, because each ini file may include
    // multiple other ini files, or map files.
    //
    // The first included ini file (or map file) is stored as
    // node->firstChild, and the next included ini file (or map file) is
    // stored as node->firstChild->sibling.  The chain of siblings is a
    // singly-linked list, though each sibling links back to his parent.
    //
    // The graph is traversed in a forward direction for every request,
    // to evaluate if any of the config files have changed, in which
    // case the config is marked as stale, and is re-read in its entirety.
    //
    // The graph is built in a forward direction during reading of the
    // ini files.  For each ini file, after all lines in the included
    // ini file have been read, one step is taken backwards in the
    // graph.
    //
    struct _IniFileItem *parent;
    struct _IniFileItem *firstChild;
    struct _IniFileItem *sibling;
} IniFileItem;



typedef struct _TextMapItem {
    char * key;

    // For a txt map, value is simply a string.  For a rnd map,
    // this starts life as a string, but then is strtok'd to
    // replace all divider chars with \0.  It is terminated with
    // a double \0.  In that way it's a series of strings.
    //
    // In either case it is allocated and must be free'd when
    // the textmap is refreshed.

    char * value;

    int nValues;   // meaningful only in rnd map
    int * indexes; // allocated and meaningful only in rnd map
} TextMapItem;


typedef struct _TextMap {
    char * fileName;
    int length;
    TextMapItem *items;
} TextMap;



typedef struct _RewriteMap {
    char * name;

    // type: 0 = txt, 1 = rnd.
    // There are no other valid values, currently.
    int type;

    union
    {
        TextMap *textMap;
        TextMap *rndMap;  // Only a notational difference.
    } u;
    struct _RewriteMap *next;
} RewriteMap;


typedef struct _ProxyPassReverse {
    char * url;
    char * path;
    int L1;
    struct _ProxyPassReverse * next;
} ProxyPassReverse;


typedef struct _ArchivedStatusMessage {
    char *Text;
    int Flavor; // 0 = ERROR, 1 = WARNING, 2 = EVENT
    struct _ArchivedStatusMessage *Next;
} ArchivedStatusMessage;


/// <summary>
///   Holds all configuration information associated to a particular
///   vdir or "application".
/// </summary>
///
/// <remarks>
///   <para>
///     There is one of these per ApplMdPath, or virtual
///     directory. (There's a concept in IIS known as "Application" but
///     it is different than a "virtual directory" in only a small
///     way. See
///     http://learn.iis.net/page.aspx/150/understanding-sites-applications-and-virtual-directories-in-iis-70/)
///     The structure is filled with content from the IIRF.ini file, or
///     files included by same, via ReadNewSiteConfig().
///   </para>
///   <para>
///     For every request, the filter checks the modified time of each
///     of the ini files, and reads in a new structure if any of the
///     times is changed.  Map files are also included in that
///     per-request check.
///   </para>
///   <para>
///     Because the structure can be read within the context of multiple
///     requests, we can't simply free the structure when any of the
///     files change.  So the structure is also refcounted, and the free
///     occurs when the siteconfig is stale, AND when the last reader is
///     finished.  This is done in ReleaseOrExpireSiteConfig().
///   </para>
///
/// </remarks>
///
typedef struct _IirfVdirConfig {
    int                     RefCount;
    int                     Era;
    boolean                 Expired;
    char                    *ApplMdPath;  // must free
    char                    *Vdir;        // must not free
    int                     numRequestsServed;
    SYSTEMTIME              ConfigRead;
    int                     nErrors;
    int                     nWarnings;
    int                     nRules;
    ArchivedStatusMessage   *statusMsgs;
    int                     nLines;
    int                     nFiles;
    IniFileItem             *IniChain;
    boolean                 RewriteBase_IsSpecified;
    boolean                 UrlDecoding_IsSpecified;
    boolean                 ProxyPreserveHost_IsSpecified;
    boolean                 EngineOn_IsSpecified;
    boolean                 StatusUrl_IsSpecified;
    // struct DReadWriteLockEx *rwl;  // read-write lock to manage access to this data structure
    CRITICAL_SECTION        *pCS;  // serialize changes to this data structure

    // values set by reading the ini file
    int                     LogLevel;
    char                    *LogFileName;
    int                     IterationLimit;
    int                     MaxMatchCount;
    char                    CondSubstringBackrefFlag; // default '*'
    char                    ConversionFlagChar; // default '#'
    char                    *StatusUrl;

    char                    *RewriteBase;  // either NULL or an allocated char pointer.

    boolean                 UrlDecoding;
    boolean                 EngineOn;
    boolean                 AllowRemoteStatus;
    boolean                 ProxyPreserveHost;
    RewriteRule             *rootRule;
    RewriteMap              *rootMap;
    ProxyPassReverse        *rootPpr;
    int                     ProxyTimeout[4]; // Resolve, Connect, Send, Receive
    LogFileEntry            *pLogFile;
    struct                  _IirfVdirConfig * Next;  // linked list

} IirfVdirConfig;



typedef struct _CachedLogMessage {
    char *Data;
    int Level;
    struct _CachedLogMessage *Next;
} CachedLogMessage;


typedef struct _IirfServerConfig {
    DWORD      FilterPriority;

    // setting this to TRUE will enable (SF_NOTIFY_LOG) and thus disable
    // kernel-mode cache in IIS6.
    boolean    WantNotifyLog;
    boolean    WantNotifyLog_IsSpecified;

    boolean    EnableStatusInquiry;
    boolean    EnableStatusInquiry_IsSpecified;

    boolean    EngineOff;
    boolean    EngineOff_IsSpecified;

    boolean    WantEventsForIniOpen;
    boolean    WantEventsForIniOpen_IsSpecified;

    char       DllLocation[_MAX_PATH];  // for logging purposes
    char       DllModuleFname[_MAX_FNAME];
    char       IniFileName[_MAX_PATH];
    BOOL       Testing;
    int        MaxFieldLength;
    int        nWarnings;
    int        nLines;
    SYSTEMTIME StartupTime ;
    char       * IniLastUpdated ; // formatted  timestring

    CachedLogMessage * MsgCache;
} IirfServerConfig;



#endif
