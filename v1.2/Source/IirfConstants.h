// Copyright (c) Microsoft Corporation, 2005, 2006, 2007.  All rights reserved.

#ifndef IIRF_CONSTANTS_H
#define IIRF_CONSTANTS_H


#define DEFAULT_LOG_LEVEL 0
#define ITERATION_LIMIT_DEFAULT 8
#define ITERATION_LIMIT_MAX 30
#define ITERATION_LIMIT_MIN 1
#define MAX_MATCH_COUNT_DEFAULT 10
#define MAX_MATCH_COUNT_MAX 25
#define MAX_MATCH_COUNT_MIN 4
#define COND_SUBSTRING_BACKREF_FLAG_DEFAULT '%';

#define STRICT_PARSING_DEFAULT TRUE

#define REDIRECT_CODE_DEFAULT 302
#define REDIRECT_CODE_MAX 399
#define REDIRECT_CODE_MIN 301


// directives:

#define DIRECTIVE_REWRITE_RULE         "RewriteRule"
#define DIRECTIVE_REWRITE_ENGINE       "RewriteEngine"
#define DIRECTIVE_REDIRECT_RULE        "RedirectRule"
#define DIRECTIVE_REWRITE_HEADER       "RewriteHeader"
#define DIRECTIVE_ITERATION_LIMIT      "IterationLimit"
#define DIRECTIVE_MAX_MATCH_COUNT      "MaxMatchCount"
#define DIRECTIVE_REWRITE_COND         "RewriteCond"
#define DIRECTIVE_REWRITE_LOG_LEVEL    "RewriteLogLevel"
#define DIRECTIVE_REWRITE_LOG_FILE     "RewriteLog"
#define DIRECTIVE_FILTER_PRIORITY      "RewriteFilterPriority"
#define DIRECTIVE_COND_SUBSTRING_FLAG  "CondSubstringBackrefFlag"
#define DIRECTIVE_STRICT               "StrictParsing"
#define DIRECTIVE_STATUS_URL           "StatusUrl"


// Directives still needing implementation: 
//#define PROXY_PASS   "ProxyPass"
//#define PROXY_PASS_REVERSE   "ProxyPassReverse"
//#define RECEIVE_BUFFER_SIZE "ProxyReceiveBufferSize"
//#define IO_BUF_SIZE  "ProxyIOBufferSize"



#endif
