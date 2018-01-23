/*

  IirfConstants.h

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2011.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  or, see Rewriter.c for the details of the license.

  Last saved:
  Time-stamp: <2011-October-03 13:57:17>

*/


#ifndef IIRF_CONSTANTS_H
#define IIRF_CONSTANTS_H


#define LOG_LEVEL_DEFAULT                   1
#define ITERATION_LIMIT_DEFAULT             8
#define ITERATION_LIMIT_MAX                 30
#define ITERATION_LIMIT_MIN                 0
#define MAX_MATCH_COUNT_DEFAULT             10
#define MAX_MATCH_COUNT_MAX                 25
#define MAX_MATCH_COUNT_MIN                 4
#define HTTP_TIMEOUT_MIN                    0
#define HTTP_TIMEOUT_MAX                    600
#define HTTP_TIMEOUT_DEFAULT                30

#define COND_SUBSTRING_BACKREF_FLAG_DEFAULT '*'
#define CONVERSION_FLAG_DEFAULT             '#'

#define WANT_NOTIFY_LOG_DEFAULT             TRUE
#define ALLOW_REMOTE_STATUS_DEFAULT         FALSE
#define ENGINE_ON_DEFAULT                   TRUE
#define URL_DECODING_DEFAULT                TRUE
#define REWRITE_BASE_DEFAULT                FALSE
#define ENABLE_STATUS_INQUIRY_DEFAULT       TRUE
#define WANT_INI_EVENTS_DEFAULT             TRUE

#define REDIRECT_CODE_DEFAULT               302
#define REDIRECT_CODE_MAX                   399
#define REDIRECT_CODE_MIN                   301


// default and default max size of the buffer to alloc when reading a
// server variable. This also applies to reading request headers. The
// max can be set above this limit with the MaxFieldLength directive,
// which applies only in IirfGlobal.ini.
#define SERVER_VAR_BUFFER_SIZE_DEFAULT      128
#define SERVER_VAR_BUFFER_SIZE_DEFAULT_MAX  16384
#define SERVER_VAR_BUFFER_SIZE_MIN_MAX      1024
#define SERVER_VAR_BUFFER_SIZE_MAX_MAX      65536

// Number and size (in bytes) of chunks to pump when proxying.
// In the future, these could be set in the global ini file.
#define IIRF_PROXY_MAX_CHUNKS_TO_READ  1048576
#define IIRF_PROXY_CHUNK_SIZE  1024*8


// directives: site config
#define DIRECTIVE_COND_SUBSTRING_FLAG  "CondSubstringBackrefFlag"
#define DIRECTIVE_ITERATION_LIMIT      "IterationLimit"
#define DIRECTIVE_MAX_MATCH_COUNT      "MaxMatchCount"
#define DIRECTIVE_REDIRECT_RULE        "RedirectRule"
#define DIRECTIVE_REWRITE_COND         "RewriteCond"
#define DIRECTIVE_REWRITE_ENGINE       "RewriteEngine"
#define DIRECTIVE_REWRITE_HEADER       "RewriteHeader"
#define DIRECTIVE_REWRITE_LOG_FILE     "RewriteLog"
#define DIRECTIVE_REWRITE_LOG_LEVEL    "RewriteLogLevel"
#define DIRECTIVE_REWRITE_RULE         "RewriteRule"
#define DIRECTIVE_STATUS_URL           "StatusUrl"
#define DIRECTIVE_STATUS_INQUIRY       "StatusInquiry"
#define DIRECTIVE_URL_DECODING         "UrlDecoding"
#define DIRECTIVE_PROXY_PASS           "ProxyPass"
#define DIRECTIVE_PROXY_PASS_REVERSE   "ProxyPassReverse"
#define DIRECTIVE_PROXY_PRESERVE_HOST  "ProxyPreserveHost"
#define DIRECTIVE_INCLUDE              "IncludeIni"
#define DIRECTIVE_REWRITE_MAP          "RewriteMap"
#define DIRECTIVE_PROXY_TIMEOUTS       "ProxyTimeouts"
#define DIRECTIVE_REWRITE_BASE         "RewriteBase"
#define DIRECTIVE_FLAG_CHARS           "FlagCharacters"


// directives that are unique to server-wide config
#define DIRECTIVE_NOTIFY_LOG           "NotifyLog"
#define DIRECTIVE_FILTER_PRIORITY      "RewriteFilterPriority"
#define DIRECTIVE_EVENTS_FOR_INI_OPEN  "EventsForIniOpen"
#define DIRECTIVE_MAX_FIELD_LENGTH     "MaxFieldLength"

// NB: StatusInquiry and RewriteEngine are also effective in server config.

// Directives still needing implementation?:
//#define RECEIVE_BUFFER_SIZE "ProxyReceiveBufferSize"
//#define IO_BUF_SIZE  "ProxyIOBufferSize"



// event codes for the Event Log
#define IIRF_EVENT_INVALID_PARAM    1
#define IIRF_EVENT_BAD_LOGFILE      2
#define IIRF_EVENT_CANNOT_READ_INI  3


#define IIRF_DEFAULT_STATUS_URL          "/iirfStatus"
#define IIRF_REMOTE_OK_KEYWORD           "RemoteOk"
#define IIRF_DEFAULT_STATUS_URL_MARKER   ((char*)0xFFFFFF01)



#endif
