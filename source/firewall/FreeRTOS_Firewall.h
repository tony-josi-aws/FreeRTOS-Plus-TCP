/*
 * FreeRTOS+TCP <DEVELOPMENT BRANCH>
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

#ifndef FREERTOS_FIREWALL_H
    #define FREERTOS_FIREWALL_H

    #ifdef __cplusplus
    extern "C" {
    #endif

    typedef struct xFirewallRule_IPv4
    {
        uint32_t uxRuleID;
        uint32_t uxSourceIP;
        uint32_t uxSourcePort;
        uint32_t uxDestnIP;
        uint32_t uxDestnPort;
        uint8_t ucProtocol;
        uint8_t ucAction;
        uint32_t uxWildcardBitmap;

        ListItem_t xRuleListItem;

    } xFirewallRule_IPv4_t;

    void vFirewallInit( void );
    BaseType_t xFirewallFilterPackets(NetworkBufferDescriptor_t * pxNetworkBuffer);
    BaseType_t xFirewallAddRule(uint8_t * ucRuleString);
    BaseType_t xFirewallListRules(uint8_t * ucResult, uint32_t uxBufferLen);
    BaseType_t xFirewallRemoveRule(uint32_t uxRuleID);

    #ifdef __cplusplus
}     /* extern "C" */
    #endif

#endif /* FREERTOS_FIREWALL_H */