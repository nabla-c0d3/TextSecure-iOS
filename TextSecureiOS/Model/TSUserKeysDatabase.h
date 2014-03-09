//
//  TSUserKeysDatabase.h
//  TextSecureiOS
//
//  Created by Alban Diquet on 12/29/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSProtocols.h"
@class TSECKeyPair;


@interface TSUserKeysDatabase : NSObject

+(BOOL) databaseCreateUserKeysWithError:(NSError **)error;
+(void) databaseErase;

// Calling the following functions will fail if the storage master key is in a "locked" state; see TSStorageMasterKey
+(TSECKeyPair*) identityKeyWithError:(NSError **)error;
+(NSArray*) allPreKeysWithError:(NSError **)error;
+(TSECKeyPair*) preKeyWithId:(int32_t)preKeyId error:(NSError **)error;

@end
