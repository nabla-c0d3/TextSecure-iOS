//
//  TSContact.h
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 10/20/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AddressBook/AddressBook.h>


@interface TSContact : NSObject

@property (nonatomic, strong, readonly) NSString *username;     // Usually the contact's phone number but could also be an email address
@property (nonatomic) ABRecordID addressBookId;                 // Id within the device's address book
@property (nonatomic, strong) NSString *relay;                  // TODO: I don't know what this is, please explain
@property (nonatomic, assign) BOOL supportsSMS;
@property (nonatomic, strong) NSString *nextKey;
@property (nonatomic, strong) NSString *identityKey;             // TODO: This may not have to be a string
@property (nonatomic) BOOL isIdentityKeyVerified;                  // Has this user's identity key been validated



+ (instancetype) contactWithUsername:(NSString *)registeredUsername addressBookId:(ABRecordID)addressBookId;
+ (instancetype) contactWithUsername:(NSString *)registeredUsername addressBookId:(ABRecordID)addressBookId relay:(NSString *)relay supportsSMS:(BOOL)supportsSMS nextKey:(NSString *)nextKey identityKey:(NSString *)identityKey isIdentityKeyVerified:(BOOL) isIdentityKeyVerified;

- (NSString*) getUsernameLabelFromAddressBook; // The localized label for the contact's phone number (mobile, phone, work, etc.)
- (NSString*) getFullNameFromAddressBook;      // The contact's first and last names

@end
