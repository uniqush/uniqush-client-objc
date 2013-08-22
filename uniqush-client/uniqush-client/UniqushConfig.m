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

#import "UniqushConfig.h"

@implementation UniqushConfig


@synthesize compress;
@synthesize host;
@synthesize port;
@synthesize pubKey;
@synthesize service;
@synthesize timeout;
@synthesize token;
@synthesize username;


- (id)init
{
    if ((self = [super init])) {
        self.host = @"127.0.0.1";
        self.port = 8989;
        self.timeout = 60;
        self.service = @"service";
        self.token = @"";
        self.username = @"username";
        self.compress = YES;
    }
    return self;
}


- (void)dealloc
{
    self.host = nil;
    self.service = nil;
    self.token = nil;
    self.username = nil;
    self.pubKey = nil;
    [super dealloc];
}


@end
