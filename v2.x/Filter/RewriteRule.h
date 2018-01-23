/*

  RewriteRule.h

  part of Ionic's Isapi Rewrite Filter [IIRF]

  Copyright (c) Dino Chiesa, 2005-2010.  All rights reserved.

  ==================================================================

  Licensed under the MS Public License.
  http://opensource.org/licenses/ms-pl.html

  or, see Rewriter.c for the details of the license.

  Last saved:
  Time-stamp: <2011-January-10 16:42:25>

*/


#ifndef REWRITE_RULE_H
#define REWRITE_RULE_H

#include "pcre.h"   // for pcre
#include <WTypes.h> // for boolean?


typedef struct RewriteRule {
    pcre *  RE;
    char * HeaderToRewrite;
    char * Pattern;
    char * Replacement;
    int  RuleFlavor;
    //boolean IsRedirect;
    int RedirectCode;
    boolean IsForbidden;
    boolean IsNotFound;
    boolean IsGone;
    boolean IsLastIfMatch;
    boolean IsCaseInsensitive;
    boolean RecordOriginalUrl;
    boolean ProxyPreserveHost; // workitem 29415
    boolean QueryStringAppend; // workitem 19486
    boolean IsNoIteration;     // WorkItem 26212

    // any condition that applies
    struct RewriteCondition * Condition;

    // linked list
    struct RewriteRule * next;
} RewriteRule, *P_RewriteRule;


// for RuleFlavor, above
#define FLAVOR_NONE      0
#define FLAVOR_RW_URL    1
#define FLAVOR_REDIRECT  2
#define FLAVOR_RW_HEADER 3
#define FLAVOR_PROXY     4

typedef struct RewriteCondition {
    pcre * RE;
    char * TestString;
    char * Pattern;

    boolean IsCaseInsensitive;

    char SpecialConditionType; // 'f' or 'd' [and maybe more later].  0 if no special condition
    boolean IsNegated;

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
