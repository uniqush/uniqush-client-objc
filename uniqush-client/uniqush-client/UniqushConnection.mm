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

#import "UniqushConnection.h"
#import "UniqushProtocol.h"
#include "uniqush.pb.h"


using namespace uniqush;


enum {
    UNIQUSH_CONN_TAG_WRITE_DATA = 0,
    UNIQUSH_CONN_SERVER_KEY_EXCHANGE,
    UNIQUSH_CONN_CLIENT_KEY_EXCHANGE,
    UNIQUSH_CONN_TAG_READ_CMD_LEN,
    UNIQUSH_CONN_TAG_READ_CMD_DATA
};


@interface UniqushConnection ()
- (void)authenticate;
- (void)clientKeyExchange;
@end


@implementation UniqushConnection


@synthesize config;
@synthesize delegate;


- (id)initWithHost:(NSString *)host
              port:(int)port
{
    if ((self = [super init])) {
        socket = [[GCDAsyncSocket alloc] initWithDelegate:self
                                            delegateQueue:dispatch_get_main_queue()];
        // Default configuration
        config = [[UniqushConfig alloc] init];
        config.host = host;
        config.port = port;

        protocol = [[UniqushProtocol alloc] init];
    }
    return self;
}


- (void)dealloc
{
    [socket disconnectAfterReading];
    [socket release];

    self.config = nil;
    [protocol release];

    [super dealloc];
}


- (void)connect
{
    NSError *error = nil;
    BOOL connected = [socket connectToHost:config.host
                                    onPort:config.port
                               withTimeout:config.timeout
                                     error:&error];
    if (!connected) {
        NSLog(@"Error: Failed to connect - %@", [error localizedDescription]);
        //TODO delegate to client
    }
}


// Write the data directly to the wire
- (BOOL)sendData:(NSData *)data
{
    [socket writeData:data
          withTimeout:config.timeout
                  tag:UNIQUSH_CONN_TAG_WRITE_DATA];
    return YES;
}


- (void)clientKeyExchange
{
    int serverKex = [protocol bytesToReadForServerKeyExchange:config.pubKey];
    [socket readDataToLength:serverKex
                 withTimeout:-1
                         tag:UNIQUSH_CONN_SERVER_KEY_EXCHANGE];
}


- (void)authenticate
{
    Command cmd;
    cmd.set_type(CMD_AUTH);
    if ([config.service length]) {
        Command_Param *param = cmd.add_params();
        param->set_param([config.service UTF8String]);
    }
    if ([config.username length]) {
        Command_Param *param = cmd.add_params();
        param->set_param([config.username UTF8String]);
    }
    if ([config.token length]) {
        Command_Param *param = cmd.add_params();
        param->set_param([config.token UTF8String]);
    }
    NSData *data = [protocol writeCommand:&cmd
                                 compress:NO];
    [self sendData:data];

    // Read server response
    [socket readDataToLength:[protocol bytesToReadForCommandLength]
                 withTimeout:-1
                         tag:UNIQUSH_CONN_TAG_READ_CMD_LEN];
}


- (void)commandIn:(NSData *)data
{
    
}


#pragma mark GCDAsyncSocketDelegate

- (void)socket:(GCDAsyncSocket *)sock
didConnectToHost:(NSString *)host
          port:(uint16_t)port
{
    NSLog(@"Starting handshake");
    [self clientKeyExchange];
}


- (void)socket:(GCDAsyncSocket *)sock
   didReadData:(NSData *)data
       withTag:(long)tag
{
    switch (tag) {
        case UNIQUSH_CONN_SERVER_KEY_EXCHANGE:
        {
            NSData *reply = [protocol replyToServerKeyExchange:data
                                                  clientRSAKey:config.pubKey
                                                         error:nil];
            [self sendData:reply];
            [self authenticate];
        }
            break;
        case UNIQUSH_CONN_TAG_READ_CMD_LEN:
        {
            if ([data length] != [protocol bytesToReadForCommandLength]) {
                NSLog(@"Err: corrupted command length");
                //TODO
            } else {
                uint16_t cmdLen = *(uint16_t *)[data bytes];
                NSLog(@"Ready for receiving command: %u bytes", cmdLen);
                [socket readDataToLength:cmdLen
                             withTimeout:-1
                                     tag:UNIQUSH_CONN_TAG_READ_CMD_DATA];
            }
        }
            break;
        case UNIQUSH_CONN_TAG_READ_CMD_DATA:
        {
            [self commandIn:data];
        }
            break;
        default:
            break;
    }
}


- (void)socketDidCloseReadStream:(GCDAsyncSocket *)sock
{

}


- (void)socketDidDisconnect:(GCDAsyncSocket *)sock
                  withError:(NSError *)err
{
    
}


@end
