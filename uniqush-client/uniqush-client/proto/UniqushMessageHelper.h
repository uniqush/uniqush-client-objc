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
#include <openssl/rsa.h>

#include "uniqush.pb.h"
#include "snappy.h"


#define EncKeyLen  32
#define AuthKeyLen 32
#define IvLen      16
#define BlkLen     16
#define HmacLen    32
#define PSSSaltLen 32
#define DHGroupID  0
#define DHPubKeyLen 256
#define NonceLen   32

#define CMDFLAG_COMPRESS 1


@class DHKey;
@class DHGroup;


@interface UniqushMessageHelper : NSObject
{
    struct snappy_env snappy;

    DHKey *cliKey;
    DHGroup *cliGroup;
    
    NSData *serverEncKey;
    NSData *serverAuthKey;
    NSData *clientEncKey;
    NSData *clientAUthKey;
}


@property(nonatomic, readonly, retain) DHGroup *cliGroup;
@property(nonatomic, readonly, retain) DHKey *cliKey;
@property(nonatomic, readonly, retain) NSData *serverEncKey;
@property(nonatomic, readonly, retain) NSData *clientEncKey;
@property(nonatomic, readonly, retain) NSData *serverAuthKey;
@property(nonatomic, readonly, retain) NSData *clientAuthKey;


- (NSData *)encode:(uniqush::Command *)cmd
          compress:(BOOL)compress;
// Caller must free the returned Command object
- (uniqush::Command *)decode:(NSData *)data;

- (void)generateKeys:(NSData *)secrete
               nonce:(NSData *)nonce;
- (void)hmacWithKey:(NSData *)key
            message:(NSData *)message
             output:(unsigned char *)output;
- (int)verifyRSAPSS:(const char *)buf
             length:(int)length
          serverSig:(const char *)sig
                key:(NSData *)key;

- (NSData *)encrypt:(NSData *)data;
- (NSData *)decrypt:(NSData *)data;

- (RSA *)PEMToRSA:(NSData *)pemData;

@end
