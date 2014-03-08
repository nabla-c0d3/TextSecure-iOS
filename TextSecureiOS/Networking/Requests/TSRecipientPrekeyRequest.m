//
//  TSGetRecipientPrekey.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 11/30/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSRecipientPrekeyRequest.h"
#import "TSContact.h"
@implementation TSRecipientPrekeyRequest

-(TSRequest*) initWithRecipient:(NSString *) contactUsername {
  NSString* recipientInformation;
    
    // TODO: What follows is never called because the contact is currently always "fake"; see the code calling this method
    // Commenting it out so I can keep on refactoring
#if 0
  if([contact.relay length]){
    recipientInformation = [NSString stringWithFormat:@"%@?%@",contact.username,contact.relay];
      // TODO for refactoring: fech the contact (and so the relay) from the DB using the contactUsername
  }
  else {
    recipientInformation=contact.username;
  }
#endif
    
    self = [super initWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"%@/%@", textSecureKeysAPI, contactUsername]]];
    [self setHTTPMethod:@"GET"];
  
    return self;
}

@end
