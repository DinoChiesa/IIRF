// Copyright (c) Microsoft Corporation, 2005, 2006, 2007.  All rights reserved.

#ifndef REWRITE_RULE_H
#define REWRITE_RULE_H

#include "pcre.h"  /* for pcre */
#include <WTypes.h>  /* for boolean? */


typedef struct RewriteRule {
    pcre *  RE;
    char * HeaderToRewrite;
    char * Pattern;
    char * Replacement;
    boolean IsRedirect;
    int RedirectCode;
    boolean IsForbidden;
    boolean IsNotFound;
    boolean IsGone;
    boolean IsLastIfMatch;
    boolean IsCaseInsensitive;
    boolean RecordOriginalUrl;
    boolean QueryStringAppend;

    // any condition that applies
    struct RewriteCondition * Condition;

    // doubly-linked list
    struct RewriteRule * next;
  //struct RewriteRule * previous;
} RewriteRule, *P_RewriteRule;



typedef struct RewriteCondition {
    pcre * RE;
    char * TestString;
    char * Pattern;

    boolean IsCaseInsensitive;

    char SpecialConditionType; // 'f' or 'd' [and maybe more later].  0 if no special condition
    boolean IsSpecialNegated; 

    // LogicalOperator
    // 0= AND, 1= OR.  Applies to the successive RewriteCond in the ini file.
    // It is meaningful only if child != NULL. 

    int LogicalOperator; 

    struct RewriteCondition * Child;

} RewriteCondition, *P_RewriteCondition;


typedef struct PcreMatchResult {

    // the subject string being matched
    char * Subject;

    // the number of matches found
    int MatchCount;

    // Vector of integers - the indexes into the Subject string. 
    // Index[2n]= start of substring n.
    // Index[2n+1]= length? of substring n.
    int  * SubstringIndexes;

} PcreMatchResult;


#endif
