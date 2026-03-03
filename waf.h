/* waf.h
# =============================================================================
# Project Name: C Middleware WAF
# File: waf.h
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
*/

#ifndef WAF_H
#define WAF_H

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

DLL_EXPORT int waf_init(const char* config_file);
DLL_EXPORT int waf_inspect(
    const char* src_ip,
    const char* method,
    const char* path,
    const char* host,
    const char** headers,
    size_t headers_count,
    const char* body,
    const char* query
);
DLL_EXPORT void waf_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif