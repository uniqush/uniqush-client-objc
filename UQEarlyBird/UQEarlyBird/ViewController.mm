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

#import "AppDelegate.h"
#import "ViewController.h"
#import "UniqushClient.h"
#import "UniqushConfig.h"
#import "UniqushConnection.h"


@interface ViewController ()
{
    UniqushConnection *connection;
}


@property(nonatomic, retain) UniqushConnection *connection;


@end


@implementation ViewController


@synthesize connection;


- (void)dealloc
{
    self.connection = nil;
    [super dealloc];
}


- (void)viewDidLoad
{
    [super viewDidLoad];

    //Test
    AppDelegate *app = (AppDelegate *)[UIApplication sharedApplication].delegate;
    self.connection = [app.client connectionWithHost:@"127.0.0.1"
                                                port:8964];
    self.connection.config.username = @"user_ios";
    
    // Get sample pub key
    NSString *pub = [[NSBundle mainBundle] pathForResource:@"pub"
                                                    ofType:@"pem"];
    self.connection.config.pubKey = [NSData dataWithContentsOfFile:pub];
    [self.connection connect];
}


- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
}


@end
