//
//  TSThread.h
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 01/12/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSProtocols.h"

@class TSMessage;


@interface TSThread : NSObject

@property (nonatomic, strong, readonly) NSString *threadID;         // A hash of all the participants' phone numbers / usernames
@property (nonatomic, strong, readonly) NSArray *participants;      // An array of usernames; does not include the current user
@property (nonatomic, retain) TSMessage *latestMessage;
//@property (nonatomic, retain) TSAxolotlThreadState *axolotlVariables;


+ (instancetype) threadWithContact:(NSString *)contactUsername;
//+ (instancetype) threadWithGroup:(NSArray *)contactsUsernames; // For group threads later;



@end
