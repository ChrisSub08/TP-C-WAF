/* 
# =============================================================================
# Project Name: C Middleware WAF
# File: waf.c
# Description: This project provides a configurable middleware WAF implemented in C.
#
# Copyright (c) 2026 Christophe SUBLET, Esisar, CyberSkills
#
# This file is part of C Middleware WAF
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =============================================================================

# Linux
gcc -fPIC -c waf.c -o waf.o
gcc -shared -o libwaf.so waf.o -Wall -O2 -pthread

# MinGW
gcc -shared -o waf.dll waf.c -Wl,--out-implib,libwaf.a

# MSVC
cl /LD waf.c /Fe:waf.dll
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <regex.h>
#include <arpa/inet.h>
#include "waf.h"

/*
Represents a rule in a linked list of rules.

Each Rule instance contains the data defining the rule itself
and a reference to the next rule in the list. This structure
allows rules to be chained together efficiently, supporting
sequential traversal and append operations.
*/
typedef struct Rule {
    char src_ip[64];

    char method[256];
    char path[256];
    char host[256];
    char headers[512];
    char body[512];
    char query[512];
    char content[512];

    char description[512];

    int score;

    /*
        Complétez la structure pour pouvoir
        l'utiliser dans une liste chainée.
    */
} Rule;

static Rule* rule_list = NULL;
static Rule* rule_tail = NULL;

/*
Prints a Rule structure for debugging purposes.

This function displays the content of a Rule instance in a
human-readable format to help developers inspect its internal
state during debugging.
*/
static void print_rule(Rule* rule) {
    printf(
        "Rule: %p \n\tsrc ip: %s \n\tmethod: %s \n\tpath: %s \n\thost: %s \n\theaders: %s \n\tbody: %s \n\tquery: %s \n\tcontent: %s \n\tscore:%i\n",
        rule,
        rule->src_ip,
        rule->method,
        rule->path,
        rule->host,
        rule->headers,
        rule->body,
        rule->query,
        rule->content,
        rule->score
    );
}

/*
Replaces the last character of a string or character buffer with a
null terminator ('\\0') if it is a newline ('\\n') or carriage return ('\\r').
*/
static void trim_newline(char* s) {
    /*
        Complétez la fonction.
    */
}

/*
Replaces the last character of a string or character buffer with a
null terminator ('\\0') if it is a semicolon (';').
*/
static void remove_trailing_semicolon(char* s) {
    /*
        Complétez la fonction.
    */
}

/*
This function adds the given Rule instance to the end of a linked list
without traversing the entire list. It uses `rule_tail` to directly
link the new rule at the end, updating the tail pointer accordingly.
*/
static void add_rule(Rule* rule) {
    /*
        Complétez la fonction.
    */
}

/*
Determines whether an IP address matches a given Rule.

his function checks if the provided IP address either:
1. Exactly matches the IP specified in the rule, or
2. Falls within the network range defined by the rule in
   CIDR notation (e.g., X.X.X.X/X)
*/
static int ip_matches(const char* rule_ip, const char* client_ip) {
    if (rule_ip[0] == '\0') return 1;

    char ip_copy[64];
    strncpy(ip_copy, rule_ip, sizeof(ip_copy) - 1);
    ip_copy[sizeof(ip_copy) - 1] = '\0';

    char* slash = strchr(ip_copy, '/');

    if (!slash) {
        return strcmp(rule_ip, client_ip) == 0;
    }

    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return 0;

    uint32_t rule_addr = 0;
    uint32_t client_addr = 0;

    if (inet_pton(AF_INET, ip_copy, &rule_addr) != 1) return 0;
    if (inet_pton(AF_INET, client_ip, &client_addr) != 1) return 0;

    uint32_t mask = (prefix == 0) ? 0 : htonl(~((1u << (32 - prefix)) - 1));
    return (rule_addr & mask) == (client_addr & mask);
}

/*
Checks whether a given string matches a regular expression pattern.

This function evaluates the provided string against the specified
regular expression. It returns True if the pattern matches any part
of the string, and False otherwise.
*/
static int regex_match(const char* pattern, const char* value) {
    if (pattern[0] == '\0') return 1;
    if (!value) return 0;

    regex_t regex;
    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE) != 0) return 0;
    int result = regexec(&regex, value, 0, NULL, 0);

    regfree(&regex);
    return result == 0;
}

/*
Initializes rules from a configuration file.

This function reads the specified configuration file, parses each
rule definition, and constructs a linked list of Rule instances.
*/
DLL_EXPORT int waf_init(const char* config_file) {

    /*
        Complétez la fonction.
    */

    if (key[0] == '#') {
        continue;
    }
    else if (strcmp(key, "SCORE") == 0) {
        if (current_rule->score) fprintf(stderr, "WARNING: %s already defined.\n", key);
        current_rule->score = atoi(value);
    }
    else if (strcmp(key, "SRC") == 0) {
        if (strlen(current_rule->src_ip)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->src_ip, value, sizeof(current_rule->src_ip) - 1);
        defined = 1;
    }
    else if (strcmp(key, "METHOD") == 0) {
        if (strlen(current_rule->method)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->method, value, sizeof(current_rule->method) - 1);
        defined = 1;
    }
    else if (strcmp(key, "PATH") == 0) {
        if (strlen(current_rule->path)) fprintf(stderr, "WARNING: %s already defined. %s %p\n", key, current_rule->path, current_rule->path);
        strncpy(current_rule->path, value, sizeof(current_rule->path) - 1);
        defined = 1;
    }
    else if (strcmp(key, "HOST") == 0) {
        if (strlen(current_rule->host)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->host, value, sizeof(current_rule->host) - 1);
        defined = 1;
    }
    else if (strcmp(key, "HEADERS") == 0) {
        if (strlen(current_rule->headers)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->headers, value, sizeof(current_rule->headers) - 1);
        defined = 1;
    }
    else if (strcmp(key, "BODY") == 0) {
        if (strlen(current_rule->body)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->body, value, sizeof(current_rule->body) - 1);
        defined = 1;
    }
    else if (strcmp(key, "QUERY") == 0) {
        if (strlen(current_rule->query)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->query, value, sizeof(current_rule->query) - 1);
        defined = 1;
    }
    else if (strcmp(key, "CONTENT") == 0) {
        if (strlen(current_rule->content)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->content, value, sizeof(current_rule->content) - 1);
        defined = 1;
    }
    else if (strcmp(key, "DESCRIPTION") == 0) {
        if (strlen(current_rule->description)) fprintf(stderr, "WARNING: %s already defined.\n", key);
        strncpy(current_rule->description, value, sizeof(current_rule->description) - 1);
    } else {
        fprintf(stderr, "WARNING: Invalid key name: %s\n", key);
    }

    /*
        Complétez la fonction.
    */
    return 1;
}

/*
Checks whether at least one header matches the given regex pattern.

This function iterates over all headers and tests each one against
the provided regular expression pattern. It returns 1 as soon as
a matching header is found, allowing for efficient short-circuit evaluation.
If no headers match the pattern, it returns 0.
*/
int headers_match(const char* pattern, const char** headers, size_t count) {
    if (!pattern) return 1;
    if (!headers || count == 0) return 0;

    for (size_t i = 0; i < count; i++) {
        if (headers[i] && regex_match(pattern, headers[i])) {
            return 1;
        }
    }

    return 0;
}

/*
Function to evaluate rules and return the score of the first matching rule.

This function iterates over a linked list of Rule instances. For each rule,
it checks whether all of its conditions are satisfied by the current configuration.
As soon as a rule matches, the function immediately returns the score associated
with that rule. If no rules match, the function returns 0.
*/
DLL_EXPORT int waf_inspect(
    const char* src_ip,
    const char* method,
    const char* path,
    const char* host,
    const char** headers,
    size_t headers_count,
    const char* body,
    const char* query
) {
    /*
        Complétez la fonction.
    */

    if (
        ip_matches(current->src_ip, src_ip) &&
        regex_match(current->method, method) &&
        regex_match(current->path, path) &&
        regex_match(current->host, host) &&
        headers_match(current->headers, headers, headers_count) &&
        regex_match(current->query, query) &&
        regex_match(current->body, body) &&
        (
            regex_match(current->content, body) ||
            regex_match(current->content, query)
        )
    ) {
        // print_rule(current);
        // printf("With: %s %s %s %s\n", src_ip, path, query, body);
        return current->score;
    }

    /*
        Complétez la fonction.
    */

    return 0;
}

/*
Clears the entire linked list of rules.

This function traverses the linked list starting from the head (`rule_list`)
and deallocates each Rule instance, effectively emptying the list.
*/
DLL_EXPORT void waf_cleanup(void) {

    /*
        Complétez la fonction.
    */
}