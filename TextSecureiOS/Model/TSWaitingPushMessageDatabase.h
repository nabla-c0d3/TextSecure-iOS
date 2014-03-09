//
//  TSWaitingPushMessageDatabase.h
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/7/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface TSWaitingPushMessageDatabase : NSObject

+(BOOL) databaseCreateWaitingPushMessageDatabaseWithError:(NSError **)error;
+(void) databaseErase;

+(void) queuePush:(NSDictionary*)pushMessageJson;
+(void) finishPushesQueued;
+(NSArray*) getPushesInReceiptOrder;
@end
