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

/**
 * @file FreeRTOS_Firewall.c
 * @brief Implements a basic firewall to allow or disallow packets.
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IPv4_Sockets.h"
#include "FreeRTOS_IPv6_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_DNS.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_Routing.h"

#include "FreeRTOS_Firewall.h"

/** @brief The list that contains the firewall rules for IPv4 packets
 */
List_t xFirewallRulesList_IPv4;

BaseType_t xFirewallInitialized = pdFALSE;

uint32_t xCurrRuleID = 0;

/**
 * @brief Initialise the Firewall.
 */
void vFirewallInit( void )
{
    vListInitialise( &xFirewallRulesList_IPv4 );
    xFirewallInitialized = pdTRUE;
}

static BaseType_t xConvertStringToInt(char *ucToken, uint32_t * uxInt)
{
    BaseType_t xResult = pdPASS;
    uintmax_t uxNum = strtoumax(ucToken, NULL, 10);
    if (uxNum == UINTMAX_MAX && errno == ERANGE)
    {
        xResult = pdFAIL;
    }
    (* uxInt) = (uint32_t) uxNum;

    return xResult;
}

static BaseType_t xRuleParser_IPv4(xFirewallRule_IPv4_t *xRuleObj, uint8_t * ucRuleString)
{
    BaseType_t xResult = pdPASS;
    uint32_t uxTokenCount = 0;
    uint32_t uxSourceIP;
    uint32_t uxSourcePort;
    uint32_t uxDestnIP;
    uint32_t uxDestnPort;
    uint32_t ucProtocol;
    uint32_t ucAction;
    uint32_t uxWildcardBitmap;

    char *ucCurrToken = strtok((char *) ucRuleString, " ");
   
    while (ucCurrToken != NULL && xResult == pdPASS)
    {
        ucCurrToken = strtok(NULL, "-");
        switch (uxTokenCount)
        {
            case 0:
                if(*ucCurrToken == '*')
                {
                    uxWildcardBitmap |= (1 << 0);
                }
                else
                {
                    xResult |= FreeRTOS_inet_pton4(ucCurrToken, &uxSourceIP);
                }
                break;
            
            case 1:
                if(*ucCurrToken == '*')
                {
                    uxWildcardBitmap |= (1 << 1);
                }
                else
                {
                    xResult |= xConvertStringToInt(ucCurrToken, &uxSourcePort);
                }
                break;

            case 2:
                if(*ucCurrToken == '*')
                {
                    uxWildcardBitmap |= (1 << 2);
                }
                else
                {
                    xResult |= FreeRTOS_inet_pton4(ucCurrToken, &uxDestnIP);
                }
                break;

            case 3:
                if(*ucCurrToken == '*')
                {
                    uxWildcardBitmap |= (1 << 3);
                }
                else
                {
                    xResult |= xConvertStringToInt(ucCurrToken, &uxDestnPort);
                }
                break;

            case 4:
                if(*ucCurrToken == '*')
                {
                    uxWildcardBitmap |= (1 << 4);
                }
                else
                {
                    xResult |= xConvertStringToInt(ucCurrToken, &ucProtocol);
                }
                break;

            case 5:
                xResult |= xConvertStringToInt(ucCurrToken, &ucAction);
                break;

            default:
                break;
        }
        uxTokenCount++;
    }

    if(uxTokenCount >= 6 && xResult == pdPASS)
    {
        xRuleObj->uxSourceIP = uxSourceIP;
        xRuleObj->uxDestnIP = uxDestnIP;
        xRuleObj->uxSourcePort = uxSourcePort;
        xRuleObj->uxDestnPort = uxDestnPort;
        xRuleObj->ucProtocol = (uint8_t) ucProtocol;
        xRuleObj->ucAction = (uint8_t) ucAction;
        xRuleObj->uxWildcardBitmap = uxWildcardBitmap;
    }

    return xResult;
}

static BaseType_t xCompareRule_IPv4(xFirewallRule_IPv4_t *xRuleObj, NetworkBufferDescriptor_t * pxNetworkBuffer)
{
    BaseType_t xMatch = pdFALSE;
    BaseType_t xResult = pdPASS;
    const ProtocolPacket_t * pxPacket = ( ( const ProtocolPacket_t * ) pxNetworkBuffer->pucEthernetBuffer );
    uint16_t usFrameType = pxPacket->xUDPPacket.xEthernetHeader.usFrameType;

    switch( usFrameType )
    {
        
        case ipIPv4_FRAME_TYPE:
            if(
                (xRuleObj->uxWildcardBitmap & (1 << 0) || xRuleObj->uxSourceIP == pxPacket->xUDPPacket.xIPHeader.ulSourceIPAddress) &&
                (xRuleObj->uxWildcardBitmap & (1 << 1) || xRuleObj->uxDestnIP == pxPacket->xUDPPacket.xIPHeader.ulDestinationIPAddress) &&
                (xRuleObj->uxWildcardBitmap & (1 << 4) || xRuleObj->uxSourcePort == pxPacket->xUDPPacket.xIPHeader.ucProtocol)
            )
            {
                xMatch = pdTRUE;
            }

            if(xMatch)
            {
                switch (pxPacket->xUDPPacket.xIPHeader.ucProtocol)
                {
                    case ipPROTOCOL_ICMP:
                        break;
                    case ipPROTOCOL_UDP:
                        if(
                            !((xRuleObj->uxWildcardBitmap & (1 << 2) || xRuleObj->uxSourcePort == pxPacket->xUDPPacket.xUDPHeader.usSourcePort) &&
                            (xRuleObj->uxWildcardBitmap & (1 << 3) || xRuleObj->uxDestnPort == pxPacket->xUDPPacket.xUDPHeader.usDestinationPort))
                        )
                        {
                            xMatch = pdFALSE;
                        }
                        break;

                    #if ipconfigUSE_TCP == 1
                        case ipPROTOCOL_TCP:
                            if(
                                !((xRuleObj->uxWildcardBitmap & (1 << 2) || xRuleObj->uxSourcePort == pxPacket->xTCPPacket.xTCPHeader.usSourcePort) &&
                                (xRuleObj->uxWildcardBitmap & (1 << 3) || xRuleObj->uxDestnPort == pxPacket->xTCPPacket.xTCPHeader.usDestinationPort))
                            )
                            {
                                xMatch = pdFALSE;
                            }
                            break;
                    #endif /* if ipconfigUSE_TCP == 1 */

                    default:
                        break;
                }
            }
            break;

        default:
            configASSERT(pdFALSE);
    }

    if(xMatch == pdTRUE)
    {
        xResult = xRuleObj->ucAction;
    }

    return xResult;

}

BaseType_t xFirewallFilterPackets(NetworkBufferDescriptor_t * pxNetworkBuffer)
{
    BaseType_t xReturn = pdFALSE;
    BaseType_t xDropPacket = pdFALSE;

    /* Check if the rules list has been initialised. */
    configASSERT( listLIST_IS_INITIALISED( &xFirewallRulesList_IPv4 ) );

    const ProtocolPacket_t * pxPacket = ( ( const ProtocolPacket_t * ) pxNetworkBuffer->pucEthernetBuffer );
    uint16_t usFrameType = pxPacket->xUDPPacket.xEthernetHeader.usFrameType;

    switch( usFrameType )
    {
        case ipIPv6_FRAME_TYPE:
            break;

        case ipIPv4_FRAME_TYPE:
        vTaskSuspendAll();
        {
            const ListItem_t * pxIterator;
            const ListItem_t * pxEnd = ( ( const ListItem_t * ) &( xFirewallRulesList_IPv4.xListEnd ) );

            for( pxIterator = listGET_NEXT( pxEnd );
                    pxIterator != pxEnd;
                    pxIterator = listGET_NEXT( pxIterator ) )
            {
                xFirewallRule_IPv4_t *xRuleObj = listGET_LIST_ITEM_OWNER(pxIterator);
                if(xCompareRule_IPv4(xRuleObj, pxNetworkBuffer) == pdFALSE)
                {
                    xDropPacket = pdTRUE;
                    break;
                }
            }
        }
        ( void ) xTaskResumeAll();

        default:
            break;
    }

    if(xDropPacket == pdTRUE)
    {
        vReleaseNetworkBufferAndDescriptor(pxNetworkBuffer);
    }
    else
    {
        xReturn = pdTRUE;
    }

    return xReturn;

}

BaseType_t xFirewallAddRule(uint8_t * ucRuleString)
{

    BaseType_t xReturn = pdTRUE;

    /* Check if the rules list has been initialised. */
    configASSERT( listLIST_IS_INITIALISED( &xFirewallRulesList_IPv4 ) );

    xFirewallRule_IPv4_t *xRuleObj = pvPortMalloc(sizeof(xFirewallRule_IPv4_t));

    if(xRuleObj)
    {
        BaseType_t xReturnParser = pdTRUE;
        xReturnParser = xRuleParser_IPv4(xRuleObj, ucRuleString);
        if(xReturnParser != pdTRUE)
        {
            vPortFree(xRuleObj);
            xReturn = pdFALSE;
        }
        else
        {
            vTaskSuspendAll();
            {
                vListInitialiseItem(&(xRuleObj->xRuleListItem));
                listSET_LIST_ITEM_OWNER( &( xRuleObj->xRuleListItem ), ( void * ) xRuleObj );
                vListInsertEnd( &xFirewallRulesList_IPv4, &( xRuleObj->xRuleListItem ) );
            }
            ( void ) xTaskResumeAll();
        }
    }
    else
    {
        xReturn = pdFALSE;
    }

    return xReturn;

}

BaseType_t xFirewallListRules(uint8_t * ucResult, uint32_t uxBufferLen)
{
    /* Check if the rules list has been initialised. */
    configASSERT( listLIST_IS_INITIALISED( &xFirewallRulesList_IPv4 ) );

}

BaseType_t xFirewallRemoveRule(uint32_t uxRuleID)
{

    BaseType_t xReturn = pdFALSE;
    const ListItem_t * pxIterator;
    const ListItem_t * pxEnd = ( ( const ListItem_t * ) &( xFirewallRulesList_IPv4.xListEnd ) );

    /* Check if the rules list has been initialised. */
    configASSERT( listLIST_IS_INITIALISED( &xFirewallRulesList_IPv4 ) );

    vTaskSuspendAll();
    {
        for( pxIterator = listGET_NEXT( pxEnd );
                pxIterator != pxEnd;
                pxIterator = listGET_NEXT( pxIterator ) )
        {
            xFirewallRule_IPv4_t *xRuleObj = listGET_LIST_ITEM_OWNER(pxIterator);
            if( xRuleObj->uxRuleID == uxRuleID )
            {
                ( void ) uxListRemove( pxIterator );
                vPortFree(xRuleObj);
                xReturn = pdTRUE;
                break;
            }
        }
    }
    ( void ) xTaskResumeAll();

    return xReturn;

}

/**
 * @brief De initialise the Firewall.
 */
void vFirewallDeInit( void )
{
    const ListItem_t * pxIterator;
    const ListItem_t * pxEnd = ( ( const ListItem_t * ) &( xFirewallRulesList_IPv4.xListEnd ) );

    /* Check if the rules list has been initialised. */
    configASSERT( listLIST_IS_INITIALISED( &xFirewallRulesList_IPv4 ) );

    xFirewallInitialized = pdFALSE;

    for( pxIterator = listGET_NEXT( pxEnd );
            pxIterator != pxEnd;
            pxIterator = listGET_NEXT( pxIterator ) )
    {
        xFirewallRule_IPv4_t *xRuleObj = listGET_LIST_ITEM_OWNER(pxIterator);
        ( void ) uxListRemove( pxIterator );
        vPortFree(xRuleObj);
    }

}
