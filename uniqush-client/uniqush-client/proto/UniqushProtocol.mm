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

#import "UniqushProtocol.h"
#import "UniqushMessageHelper.h"
#import "UniqushConnection.h"

#include <openssl/rsa.h>


@interface UniqushProtocol ()
- (NSData *)swap:(NSMutableData *)data;
- (NSData *)leftPaddingZero:(NSData *)data
                     length:(int)len;
@end


@implementation UniqushProtocol


- (id)init
{
    if ((self = [super init])) {
        msgHelper = [[UniqushMessageHelper alloc] init];
    }
    return self;
}


- (void)dealloc
{
    [msgHelper release];

    [super dealloc];
}


- (NSData *)swap:(NSMutableData *)data
{
    int len = [data length];
    char *b1 = (char *)[data mutableBytes];
    char *b2 = b1 + len;

    for(--b2; b1 < b2; ++b1, --b2) {
        *b1 = *b1 ^ *b2,
        *b2 = *b1 ^ *b2,
        *b1 = *b1 ^ *b2;
    }

    return data;
}


- (NSData *)leftPaddingZero:(NSData *)data
                     length:(int)len
{
    if ([data length] >= len) {
        return data;
    }

    NSMutableData *ret = [NSMutableData dataWithLength:len - [data length]];
    [ret appendData:data];
    return ret;
}


- (int)bytesToReadForServerKeyExchange:(NSData *)rsaKey
{
    const unsigned char *rk = (const unsigned char *)[rsaKey bytes];
    RSA* rsa = d2i_RSAPublicKey(NULL, &rk, (long)[rsaKey length]);
    if (!rsa) {
        return 0;
    }
    
    const int sigLen = RSA_size(rsa);
    return 1 + DHPubKeyLen + sigLen + NonceLen;
}


- (int)bytesToReadForCommandLength
{
    // uint16_t
    return sizeof(uint16_t);
}


- (NSData *)replyToServerKeyExchange:(NSData *)data
                        clientRSAKey:(NSData *)rsaKey
                               error:(NSError **)error
{
    // - version
    // - Server's DH public key: g ^ x
    // - Signature of server's DH public key RSASSA-PSS(g ^ x)
    // - nonce

    int len = [data length] - DHPubKeyLen - 1;
    if ([data length] == 0 || len <= 0) {
        //TODO
        return nil;
    }
    
    char *buf = (char *)[data bytes];
    char version = buf[0];
    if (version != CurrentProtocolVersion) {
        //TODO
        return nil;
    }

    char *serverSigData = buf + 1 + DHPubKeyLen;

    len = [msgHelper verifyRSAPSS:buf
                           length:1 + DHPubKeyLen
                        serverSig:serverSigData
                              key:rsaKey];

    if (len == 0) {
        //TODO
        return nil;
    }

    char *serverPubData = buf + 1;
    char *nonce = buf + 1 + DHPubKeyLen + len;

    NSData *cliPub = [self leftPaddingZero:[self swap:[NSMutableData dataWithData:msgHelper.cliKey.publicKey]]
                                    length:DHPubKeyLen];
    NSData *secret = [msgHelper.cliKey computeSecretWithPublicKey:[NSData dataWithBytes:serverPubData
                                                                                 length:DHPubKeyLen]];

    [msgHelper generateKeys:secret
                      nonce:[NSData dataWithBytes:nonce
                                      length:NonceLen]];

    NSMutableData *message = [NSMutableData data];
    char ver = CurrentProtocolVersion;
    [message appendBytes:(unsigned char*)&ver
                  length:1];
    [message appendData:cliPub];
    unsigned char hmac[AuthKeyLen] = { 0 };
    [msgHelper hmacWithKey:msgHelper.clientAuthKey
                   message:message
                    output:hmac];
    [message appendBytes:hmac
                  length:AuthKeyLen];
    return message;
}


- (NSData *)writeCommand:(uniqush::Command *)command
                compress:(BOOL)compress
{
    NSData *cmdData = [msgHelper encode:command
                               compress:compress];

    uint16_t cmdLen = [cmdData length];
    if (cmdLen == 0) {
        return nil;
    }

    NSMutableData *data = [NSMutableData data];
    // Since we're using AES CTR mode, cipher and plain text have same length
    [data appendBytes:&cmdLen
               length:2];

    // We use "encrypt first, then hmac" scheme
    NSData *enc = [msgHelper encrypt:cmdData];
    [data appendData:enc];

    NSMutableData *auth = [NSMutableData dataWithLength:AuthKeyLen];
    [msgHelper hmacWithKey:msgHelper.clientAuthKey
                   message:data
                    output:(unsigned char *)[auth mutableBytes]];
    [data appendData:auth];
    return data;
}


- (uniqush::Command *)readCommand:(NSData *)data
                           length:(int)len
{
    int encLen = [data length] - AuthKeyLen;
    unsigned char *buf = (unsigned char *)[data bytes];
    NSData *hmac = [NSData dataWithBytes:buf + encLen
                                  length:AuthKeyLen];
    NSMutableData *auth = [NSMutableData dataWithLength:AuthKeyLen];
    [msgHelper hmacWithKey:msgHelper.clientAuthKey
                   message:data
                    output:(unsigned char *)[auth mutableBytes]];
    if (![auth isEqualToData:hmac]) {
        //TODO
        return nil;
    }
    NSData *enc = [NSData dataWithBytes:buf
                                 length:encLen];
    return [msgHelper decode:[msgHelper decrypt:enc]];
}


@end
