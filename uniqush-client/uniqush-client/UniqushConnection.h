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


@protocol UniqushConnectionDelegate;
@class UniqushConfig;


@interface UniqushConnection : NSObject 
{

    id<UniqushConnectionDelegate> delegate;
}


@property(nonatomic, assign) id<UniqushConnectionDelegate> delegate;
@property(nonatomic, retain) UniqushConfig *config;


- (id)initWithHost:(NSString *)host
              port:(int)port;

- (void)connect;
- (BOOL)sendData:(NSData *)data;


@end


@protocol UniqushConnectionDelegate <NSObject>



@end
