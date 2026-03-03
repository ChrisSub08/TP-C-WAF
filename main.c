/* main.c
# =============================================================================
# Project Name: C Middleware WAF
# File: main.c
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
gcc main.c -L. -lwaf -o main
LD_LIBRARY_PATH=. ./main

# MinGW
gcc main.c -L. -lwaf -o main.exe

# MSVC
cl main.c waf.lib
*/

#include <stdio.h>
#include "waf.h"

#include <stdio.h>

struct TestCase {
    const char* src_ip;
    const char* method;
    const char* path;
    const char* host;
    const char** headers;
    size_t headers_count;
    const char* body;
    const char* query;
    const char* description;
};

/*
Entry point of the test compilation process.

This function test the project's and executes it in order
to verify that the software is functioning correctly.
It ensures that all test cases are built successfully.
*/
int main(void) {

    if (!waf_init("rules.conf")) {
        printf("Failed to load rules\n");
        return 1;
    }

    const char* h_sqlmap1[] = {"User-Agent: sqlmap"};
    const char* h_curl[] = {"User-Agent: curl"};
    const char* h_normal[] = {"User-Agent: normal"};
    const char* h_test[] = {"User-Agent: test"};
    const char* h_sqlmap2[] = {"User-Agent: sqlmap/1.7.2","Accept: */*"};
    const char* h_nikto[] = {"User-Agent: Nikto/2.5.0","Host: example.com"};
    const char* h_msf[] = {"User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Metasploit)","Connection: close"};


    struct TestCase tests[] = {
        {"192.168.1.10","POST","/admin","example.com",h_sqlmap1,1,"union select * from users","","Test 1: POST /admin, SQL injection, local address"},
        {"5.5.5.5","GET","/public","example.com",h_curl,1,"","","Test 2: GET /public, public address"},
        {"1.1.1.1","POST","/login","example.com",h_normal,1,"password=1234","","Test 3: POST /login, public address"},
        {"8.8.8.8","POST","/admin","example.com",h_normal,1,"","","Test 4: POST /admin, public address"},
        {"133.122.111.100","GET","/index.php","example.com",h_test,1,"","","Test 5: GET /index.php, public address"},
        {"133.122.111.100","POST","/login","localhost",h_sqlmap1,1,"","","Test 6: POST /login, host localhost, public address"},
        {"127.0.0.1","GET","/admin","localhost",h_curl,1,"","","Test 7: POST /admin, localhost"},
        {"133.122.111.100","POST","/xmlrpc.php","example.com",h_curl,1,"","","Test 8: POST /xmlrpc.php, public address"},
        {"133.122.111.100","GET","/default.aspx","example.com",h_curl,1,"","","Test 9: GET /default.aspx, public address"},
        {"133.122.111.100","GET","/style.css","example.com",h_curl,1,"","","Test 10: GET /style.css, public address"},
        {"133.122.111.100","GET","/image.jpg","example.com",h_curl,1,"","","Test 11: GET /image.jpg, public address"},
        {"133.122.111.100","POST","/login","example.com",h_curl,1,"","<script>alert('xss')</script>","Test 12: POST /login, query XSS, public address"},
        {"133.122.111.100","POST","/login","example.com",h_curl,1,"union select * from users","","Test 13: POST /login, body SQLi, public address"},
        {"133.122.111.100","POST","/cmd","example.com",h_curl,1,"ls -la; cat /etc/passwd","","Test 14: POST /cmd, body command injection, public address"},
        {"133.122.111.100","POST","/webshell.php","example.com",h_curl,1,"eval(base64_decode('abcd'))","","Test 15: POST /webshell.php, body PHP webshell, public address"},
        {"45.12.33.10","POST","/login","example.com",h_sqlmap2,2,"username=admin&password=test","","Test 16: POST /login, SQLMap User-Agent, public address"},
        {"45.12.33.10","POST","/login","example.com",h_nikto,2,"username=admin&password=test","","Test 17: POST /login, Nikto User-Agent, public address"},
        {"45.12.33.10","POST","/login","example.com",h_msf,2,"username=admin&password=test","","Test 16: POST /login, Metasploit User-Agent, public address"}
    };

    size_t n = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < n; i++) {

        int score = waf_inspect(
            tests[i].src_ip,
            tests[i].method,
            tests[i].path,
            tests[i].host,
            tests[i].headers,
            tests[i].headers_count,
            tests[i].body,
            tests[i].query
        );

        printf("%s\n", tests[i].description);
        printf(" -> Score: %d\n", score);

        if (score >= 10)
            printf(" -> Action: BLOCK\n\n");
        else if (score >= 5)
            printf(" -> Action: ALERT\n\n");
        else
            printf(" -> Action: ALLOW\n\n");
    }

    waf_cleanup();
    return 0;
}