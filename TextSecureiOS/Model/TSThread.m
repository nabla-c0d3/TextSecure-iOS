//
//  TSThread.m
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 01/12/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSThread.h"
#import "TSMessage.h"
#import "TSContact.h"
#import "Cryptography.h"


@implementation TSThread


#pragma mark Private methods

+ (NSString*) generateThreadIdForParticipants:(NSArray*)contactsUsernames {
    // Sort the phone numbers so we always get the same hash for the same list of contacts
    NSArray *sortedArray = [contactsUsernames sortedArrayUsingDescriptors:
                            @[[NSSortDescriptor sortDescriptorWithKey:@"doubleValue"
                                                            ascending:YES]]];
    // Convert the result to a string
    NSString *phoneNumbers = [sortedArray componentsJoinedByString:@""];
    
    // Hash the string
    return [Cryptography computeSHA1DigestForString:phoneNumbers];
}



# pragma mark Thread creation method

+ (instancetype) threadWithContact:(NSString *)contactUsername {
    TSThread *thread = [[TSThread alloc] init];
    if (thread == nil) {
        return nil;
    }
    
    thread->_participants = @[contactUsername];
    thread->_threadID = [TSThread generateThreadIdForParticipants:@[contactUsername]];
    
    // TODO: Fetch latest message from DB
    
    return thread;
}

@end
