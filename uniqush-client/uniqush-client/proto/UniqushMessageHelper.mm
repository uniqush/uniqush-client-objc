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

#import "UniqushMessageHelper.h"
#import "DHKey.h"
#import "DHGroup.h"

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>


#define USE_COMMON_CRYPTO


struct CTR_STATE {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};


using namespace uniqush;


@interface UniqushMessageHelper ()
{
    struct CTR_STATE encState;
    struct CTR_STATE decState;
    AES_KEY encKey;
    AES_KEY decKey;

    CCCryptorRef encCrypto;
    CCCryptorRef decCrypto;
}


@property(nonatomic, readwrite, retain) DHGroup *cliGroup;
@property(nonatomic, readwrite, retain) DHKey *cliKey;
@property(nonatomic, readwrite, retain) NSData *serverEncKey;
@property(nonatomic, readwrite, retain) NSData *clientEncKey;
@property(nonatomic, readwrite, retain) NSData *serverAuthKey;
@property(nonatomic, readwrite, retain) NSData *clientAuthKey;


- (void)MGF1_XOR_SHA256:(NSMutableData *)data
                   seed:(NSData *)seed;
- (NSString *)dataToHex:(NSData *)data;


@end


@implementation UniqushMessageHelper


@synthesize clientAuthKey;
@synthesize clientEncKey;
@synthesize cliGroup;
@synthesize cliKey;
@synthesize serverAuthKey;
@synthesize serverEncKey;


- (id)init
{
    if ((self = [super init])) {
        snappy_init_env(&snappy);

        /* openssl initialization */
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        
        RAND_poll();

        // Generate DH key
        self.cliGroup = [DHGroup groupWithGroupId:DHGroupID];
        self.cliKey = [[[DHKey alloc] initWithDHGroup:self.cliGroup] autorelease];

        // IV: 0 for all. Since we change keys for each connection, letting IV=0 won't hurt.
        encState = { 0 };
        decState = { 0 };
    }
    return self;
}


- (void)dealloc
{
    CRYPTO_cleanup_all_ex_data();
    RAND_cleanup();
	EVP_cleanup();
	ERR_free_strings();
    ERR_remove_state(0);

    CCCryptorRelease(encCrypto);
    CCCryptorRelease(decCrypto);
    
    self.cliKey = nil;
    self.cliGroup = nil;
    self.clientEncKey = nil;
    self.clientAuthKey = nil;
    self.serverEncKey = nil;
    self.serverAuthKey = nil;

    [super dealloc];
}


- (NSData *)encode:(uniqush::Command *)cmd
          compress:(BOOL)compress
{
    NSMutableData *enc = [NSMutableData data];

    unsigned char meta[4] = { 0 };

    int numParams = cmd->params_size();
    int numHeaders = cmd->msg().headers_size();

    meta[0] = cmd->type();
    meta[1] = 0x0F & numParams;
    meta[1] = meta[1] << 4;
    meta[2] = 0xFF & ((0x0000FF00 & numHeaders) >> 8);
    meta[3] = 0xFF & numHeaders;

    [enc appendBytes:meta
              length:4];

    for (int i = 0; i < numParams; i++) {
        char nullch = 0;
        const Command_Param& param = cmd->params(i);
        [enc appendBytes:param.param().c_str()
                  length:param.param().length()];
        [enc appendBytes:&nullch
                  length:1];
    }

    const Message& msg = cmd->msg();
    for (int i = 0; i < numHeaders; i++) {
        char nullch = 0;
        const Message_Header& hdr = msg.headers(i);
        [enc appendBytes:hdr.key().c_str()
                  length:hdr.key().length()];
        [enc appendBytes:&nullch
                  length:1];
        [enc appendBytes:hdr.value().c_str()
                  length:hdr.value().length()];
        [enc appendBytes:&nullch
                  length:1];
    }
    [enc appendBytes:msg.body().c_str()
              length:msg.body().length()];

    int len = [enc length];
    unsigned char flag = 0;
    if (compress) {
        flag |= CMDFLAG_COMPRESS;
        unsigned char *cpbuf = (unsigned char *)malloc(snappy_max_compressed_length(len));
        snappy_compress(&snappy, (const char *)[enc mutableBytes],
                        [enc length], (char *)cpbuf, (size_t *)&len);
        enc = [NSMutableData dataWithBytes:cpbuf
                                    length:len];
        free(cpbuf);
    }

    int numBlk = (len + BlkLen) / BlkLen;
    int numPadding = (numBlk * BlkLen) - (len + 1);

    NSMutableData *ret = [NSMutableData dataWithLength:len + 1 + numPadding];
    char *buf = (char *)[ret mutableBytes];

    flag |= ((numPadding & 0xFF) << 3);

    buf[0] = flag;
    memcpy(buf + 1, [enc bytes], [enc length]);

#ifdef DEBUG
    NSLog(@"encoded command: %@", [self dataToHex:ret]);
#endif
    return ret;
}


- (uniqush::Command *)decode:(NSData *)data
{
#ifdef DEBUG
    NSLog(@"decode command: %@", [self dataToHex:data]);
#endif
    char *buf = (char *)[data bytes];
    int numPadding = buf[0] >> 3;
    int len = [data length] - 1 - numPadding;
    char *dec = buf + 1;
    BOOL compressed = (buf[0] & CMDFLAG_COMPRESS) != 0;
    if (compressed) {
        int uncLen = 0;
        BOOL decomp = snappy_uncompressed_length((const char *)dec, len, (size_t *)&uncLen);
        if (!decomp) {
            //TODO
            return NULL;
        }
        char *unc = (char *)malloc(uncLen);
        snappy_uncompress(dec, len, unc);
        dec = unc;
        len = uncLen;
    }

    Command *cmd = new Command;
    buf = dec;
    cmd->set_type((CommandType)dec[0]);

    int numParams = dec[1] >> 4;
    int numHdrs = dec[2];
    numHdrs = numHdrs << 8;
    numHdrs |= dec[3];

    dec += 4;

    for (int i = 0; i < numParams; i++) {
        int paramLen = strlen(dec); // strlen will stop at NULL (0) character
        Command_Param *param = cmd->add_params();
        param->set_param(dec, paramLen);
        dec += (paramLen + 1);
    }

    Message *msg = NULL;
    if (numHdrs > 0) {
        msg = cmd->mutable_msg();
        for (int i = 0; i < numHdrs; i++) {
            Message_Header *hdr = msg->add_headers();
            int keyLen = strlen(dec);
            hdr->set_key(dec, keyLen);
            dec += (keyLen + 1);
            int valLen = strlen(dec);
            hdr->set_value(dec, valLen);
            dec += (valLen + 1);
        }
    }

    if ((dec - buf) < len) {
        // still have body
        if (!msg) {
            msg = cmd->mutable_msg();
        }
        msg->set_body(dec, len - (dec - buf));
    }

    if (compressed) {
        free(dec);
    }

    return cmd;
}


- (void)MGF1_XOR_SHA256:(NSMutableData *)data
                   seed:(NSData *)seed
{
    uint32_t counter = 0;
    
    int i = 0;
    int j = 0;
    int len = [data length];
    unsigned char *buf = (unsigned char *)[data mutableBytes];
#ifdef USE_COMMON_CRYPTO
    unsigned char hashed[CC_SHA256_DIGEST_LENGTH] = { 0 };
#else
    unsigned char hashed[SHA256_DIGEST_LENGTH] = { 0 };
#endif
    for (;i < len;) {
        uint32_t oct = htonl(counter++);
        
#ifdef USE_COMMON_CRYPTO
        CC_SHA256_CTX sha_ctx;
        CC_SHA256_Init(&sha_ctx);
        CC_SHA256_Update(&sha_ctx, [seed bytes], [seed length]);
        CC_SHA256_Update(&sha_ctx, (void *)&oct, 4);
        CC_SHA256_Final(hashed, &sha_ctx);
#else
        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, [seed bytes], [seed length]);
        SHA256_Update(&sha_ctx, (void *)&oct, 4);
        SHA256_Final(hashed, &sha_ctx);
#endif
#ifdef DEBUG
        {
            char *buf = (char *)&oct;
            NSLog(@"hash[counter %d%d%d%d]: %@", buf[0], buf[1], buf[2], buf[3],
                  [self dataToHex:[NSData dataWithBytes:hashed
                                                 length:32]]);
        }
#endif
        for (j = 0; j < sizeof(hashed) && i < len; j++) {
            buf[i] ^= hashed[j];
            i++;
        }
    }
}


- (void)hmacWithKey:(NSData *)key
            message:(NSData *)message
             output:(unsigned char *)output
{
#ifdef USE_COMMON_CRYPTO
    CCHmac(kCCHmacAlgSHA256, [key bytes], [key length], [message bytes], [message length], output);
#else
    HMAC_CTX hmac_ctx;
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init(&hmac_ctx, [key bytes], [key length], EVP_sha256());
    HMAC_Update(&hmac_ctx, (const unsigned char *)[message bytes], [message length]);
    HMAC_Final(&hmac_ctx, output, NULL);
#endif
#ifdef DEBUG
    NSLog(@"HMAC: %@", [self dataToHex:[NSData dataWithBytes:output
                                                      length:AuthKeyLen]]);
#endif
}


- (NSString *)dataToHex:(NSData *)data
{
    NSUInteger capacity = [data length] * 2;
    NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:capacity];
    const unsigned char *dataBuffer = (const unsigned char *)[data bytes];
    for (int i=0; i<[data length]; ++i) {
        [stringBuffer appendFormat:@"%02X", (NSUInteger)dataBuffer[i]];
    }
    return [NSString stringWithString:stringBuffer];
}


- (void)generateKeys:(NSData *)secrete
               nonce:(NSData *)nonce
{
    NSMutableData *mkey = [NSMutableData dataWithLength:48];
    NSMutableData *seed = [NSMutableData data];
    [seed appendData:secrete];
    [seed appendData:nonce];
    
    [self MGF1_XOR_SHA256:mkey
                     seed:seed];
    

    /*
     * We are using AES-256 CTR (Counter) Cipher
     *   http://blog.agilebits.com/2013/03/09/guess-why-were-moving-to-256-bit-aes-keys/
     */
    NSMutableData *enc = [NSMutableData dataWithLength:EncKeyLen];
    NSMutableData *auth = [NSMutableData dataWithLength:AuthKeyLen];

    [self hmacWithKey:mkey
              message:[@"ClientAuth" dataUsingEncoding:NSUTF8StringEncoding]
               output:(unsigned char *)[auth mutableBytes]];
    [self hmacWithKey:mkey
              message:[@"ClientEncr" dataUsingEncoding:NSUTF8StringEncoding]
               output:(unsigned char *)[enc mutableBytes]];
    self.clientAuthKey = [NSData dataWithData:auth];
    self.clientEncKey = [NSData dataWithData:enc];

    [self hmacWithKey:mkey
              message:[@"ServerAuth" dataUsingEncoding:NSUTF8StringEncoding]
               output:(unsigned char *)[auth mutableBytes]];
    [self hmacWithKey:mkey
              message:[@"ServerEncr" dataUsingEncoding:NSUTF8StringEncoding]
               output:(unsigned char *)[enc mutableBytes]];
    self.serverAuthKey = [NSData dataWithData:auth];
    self.serverEncKey = [NSData dataWithData:enc];

#ifdef DEBUG
    NSLog(@"-------------------------------------------");
    NSLog(@"secret:");
    NSLog(@"%@", [self dataToHex:secrete]);
    NSLog(@"nonce:");
    NSLog(@"%@", [self dataToHex:nonce]);
    NSLog(@"master key:");
    NSLog(@"%@", [self dataToHex:mkey]);
    NSLog(@"client auth key:");
    NSLog(@"%@", [self dataToHex:self.clientAuthKey]);
    NSLog(@"client enc key:");
    NSLog(@"%@", [self dataToHex:self.clientEncKey]);
    NSLog(@"server auth key:");
    NSLog(@"%@", [self dataToHex:self.serverAuthKey]);
    NSLog(@"server enc key:");
    NSLog(@"%@", [self dataToHex:self.serverEncKey]);
    NSLog(@"-------------------------------------------");
#endif

#ifdef USE_COMMON_CRYPTO
    NSLog(@"Generate keys using CommonCrypto");
    if (encCrypto) {
        CCCryptorRelease(encCrypto);
    }
    if (decCrypto) {
        CCCryptorRelease(decCrypto);
    }
    /*
     * XXX: Use CCCryptorCreate here will encrypt data incorrectly, and
     *      kCCModeOptionCTR_LE is unimplemented yet.
     *        http://stackoverflow.com/questions/12529612/interoperability-of-aes-ctr-mode
     *
     *      Check source:
     *        http://www.opensource.apple.com/source/CommonCrypto/CommonCrypto-60026/Source/API/CommonCryptor.c
     */

    CCCryptorStatus ret = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES128,
                                                  ccNoPadding, NULL,
                                                  [self.clientEncKey bytes],
                                                  EncKeyLen, NULL, 0, 0,
                                                  kCCModeOptionCTR_BE,
                                                  &encCrypto);
    if (ret != kCCSuccess) {
        NSLog(@"Err: Failed to generate encryption key - %d", ret);
        self.clientEncKey = nil;
    }
    ret = CCCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES128,
                                  ccNoPadding, NULL,
                                  [self.serverEncKey bytes],
                                  EncKeyLen, NULL, 0, 0,
                                  kCCModeOptionCTR_BE,
                                  &decCrypto);
    if (ret != kCCSuccess) {
        NSLog(@"Err: Failed to generate decryption key - %d", ret);
        self.serverEncKey = nil;
    }
#else
    NSLog(@"Generate keys using OpenSSL");
    if (AES_set_encrypt_key((const unsigned char *)[self.clientEncKey bytes], EncKeyLen * 8, &encKey) < 0) {
        NSLog(@"Err: Failed to generate encryption key");
        self.clientEncKey = nil;
    }
    if (AES_set_encrypt_key((const unsigned char *)[self.serverEncKey bytes], EncKeyLen * 8, &decKey) < 0) {
        NSLog(@"Err: Failed to generate decryption key");
        self.serverEncKey = nil;
    }
    // reset ctr state
    encState = { 0 };
    decState = { 0 };
#endif
}


- (int)verifyRSAPSS:(const char *)buf
             length:(int)length
          serverSig:(const char *)sig
                key:(NSData *)key
{
    RSA* rsa = [self PEMToRSA:key];
    if (!buf || length == 0 || !rsa) {
        return 0;
    }

    const int sigLen = RSA_size(rsa);
    
#ifdef USE_COMMON_CRYPTO
    unsigned char hashed[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(buf, DHPubKeyLen + 1, hashed);
#else
    unsigned char hashed[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, buf, length);
    SHA256_Final(hashed, &sha_ctx);
#endif
    
    unsigned char *decBuf = (unsigned char *)malloc(RSA_size(rsa));
    int ret = RSA_public_decrypt(sigLen, (const unsigned char *)sig, decBuf, rsa, RSA_NO_PADDING);
    if (ret == -1) {
        RSA_free(rsa);
        free(decBuf);
        return 0;
    }
    ret = RSA_verify_PKCS1_PSS(rsa, hashed, EVP_sha256(), decBuf, 32);
    free(decBuf);
    RSA_free(rsa);
    if (ret != 1) {
        //TODO
        return 0;
    }
    return sigLen;
}


- (NSData *)encrypt:(NSData *)data
{
    unsigned char *output = (unsigned char *)calloc([data length], 1);
#ifdef USE_COMMON_CRYPTO
    size_t outputRequired = CCCryptorGetOutputLength(encCrypto, [data length], NO);
#ifdef DEBUG
    if (outputRequired != [data length]) {
        NSLog(@"Warning: incorrect encryptor is probably used - %d bytes required for output while only %d is provided", (int)outputRequired, [data length]);
    }
#endif
    CCCryptorStatus ret = CCCryptorUpdate(encCrypto,
                                          [data bytes],
                                          [data length],
                                          output,
                                          [data length],
                                          &outputRequired);
    if (ret == kCCBufferTooSmall) {
        NSLog(@"Err: insufficient output buffer (%d required), retry!", (int)outputRequired);
        output = (unsigned char *)realloc(output, outputRequired);
        ret = CCCryptorUpdate(encCrypto,
                              [data bytes],
                              [data length],
                              output,
                              outputRequired,
                              &outputRequired);
    }
    if (ret != kCCSuccess) {
        NSLog(@"Err: encryption failed");
        return nil;
    }
#else
    AES_ctr128_encrypt((const unsigned char *)[data bytes], output, [data length],
                       &encKey, encState.ivec,
                       encState.ecount, &encState.num);
#endif
    NSData *cipher = [NSData dataWithBytes:output
                                    length:[data length]];
    free(output);
#ifdef DEBUG
    NSLog(@"encrypted data: %@", [self dataToHex:cipher]);
#endif
    return cipher;
}


- (NSData *)decrypt:(NSData *)data
{
    unsigned char *output = (unsigned char *)calloc([data length], 1);
#ifdef USE_COMMON_CRYPTO
    size_t outputRequired = CCCryptorGetOutputLength(decCrypto, [data length], NO);
#ifdef DEBUG
    if (outputRequired != [data length]) {
        NSLog(@"Warning: incorrect encryptor is probably used - %d bytes required for output while only %d is provided", (int)outputRequired, [data length]);
    }
#endif
    CCCryptorStatus ret = CCCryptorUpdate(decCrypto,
                                          [data bytes],
                                          [data length],
                                          output,
                                          [data length],
                                          &outputRequired);
    if (ret == kCCBufferTooSmall) {
        NSLog(@"Err: insufficient output buffer (%d required), retry!", (int)outputRequired);
        output = (unsigned char *)realloc(output, outputRequired);
        ret = CCCryptorUpdate(decCrypto,
                              [data bytes],
                              [data length],
                              output,
                              outputRequired,
                              &outputRequired);
    }
    if (ret != kCCSuccess) {
        NSLog(@"Err: decryption failed");
        return nil;
    }
#else
    AES_ctr128_encrypt((const unsigned char *)[data bytes], output, [data length],
                       &decKey, decState.ivec,
                       decState.ecount, &decState.num);
#endif
    NSData *plain = [NSData dataWithBytes:output
                                   length:[data length]];
    free(output);
    return plain;
}


- (RSA *)PEMToRSA:(NSData *)pemData
{
    BIO *bufio;
    RSA *rsa = NULL;

    bufio = BIO_new_mem_buf((void *)[pemData bytes], [pemData length]);
    rsa = PEM_read_bio_RSA_PUBKEY(bufio, NULL, 0, NULL);
    if (!rsa) {
        ERR_print_errors_fp(stdout);
    }
    BIO_free(bufio);
    return rsa;
}


@end
