/*
 * Copyright 2013 Xueliang Hua (sakur.deagod@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#import <Foundation/Foundation.h>
#import "DHKey.h"
#import "DHGroup.h"

#include "uniqush.pb.h"


#define CurrentProtocolVersion 1

enum {
    ErrZeroEntropy = 1,
    ErrImcompatibleProtocol,
    ErrBadServer,
    ErrCorruptedData,
    ErrBadKeyExchangePacket,
    ErrBadPeerImpl
};


@class UniqushMessageHelper;


@interface UniqushProtocol : NSObject
{
    UniqushMessageHelper *msgHelper;
}


- (int)bytesToReadForServerKeyExchange:(NSData *)rsaKey;
- (int)bytesToReadForCommandLength;
- (int)bytesToReadForNextCommand:(int)cmdLen;

- (NSData *)replyToServerKeyExchange:(NSData *)data
                        clientRSAKey:(NSData *)rsaKey
                               error:(NSError **)error;
- (NSData *)replyToServerCommand:(NSData *)cmdData
                           error:(NSError **)error;

- (NSData *)writeCommand:(uniqush::Command *)command
                compress:(BOOL)compress;
// Caller must free the returned object
- (uniqush::Command *)readCommand:(NSData *)data // encrypted cmd data (plus hmac)
                           length:(int)len;      // original cmd length


@end
