//
//  TSContact.m
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 10/20/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSContactManager.h"

@implementation TSContact


+ (instancetype) contactWithUsername:(NSString *)registeredUsername addressBookId:(ABRecordID)addressBookId relay:(NSString *)relay supportsSMS:(BOOL)supportsSMS nextKey:(NSString *)nextKey identityKey:(NSString *)identityKey isIdentityKeyVerified:(BOOL) isIdentityKeyVerified {
    
    TSContact *contact = [[TSContact alloc] init];
    if (contact == nil) {
        return nil;
    }
    
    contact->_username = registeredUsername;
    contact->_addressBookId = addressBookId;
    contact->_relay = relay;
    contact->_nextKey = nextKey;
    contact->_identityKey = identityKey;
    contact->_isIdentityKeyVerified = isIdentityKeyVerified;
    
    return contact;
}

+ (instancetype) contactWithUsername:(NSString *)registeredUsername addressBookId:(ABRecordID)addressBookId {
    return [TSContact contactWithUsername:registeredUsername addressBookId:addressBookId relay:nil supportsSMS:NO nextKey:nil identityKey:nil isIdentityKeyVerified:NO];
}


- (NSString*) getFullNameFromAddressBook {
    if (self.addressBookId){
        
        ABAddressBookRef addressBook = ABAddressBookCreateWithOptions(nil, nil);
        
        ABRecordRef currentPerson = ABAddressBookGetPersonWithRecordID(addressBook, self.addressBookId);
        NSString *firstName = (__bridge NSString *)ABRecordCopyValue(currentPerson, kABPersonFirstNameProperty) ;
        NSString *surname = (__bridge NSString *)ABRecordCopyValue(currentPerson, kABPersonLastNameProperty) ;
        
        CFRelease(addressBook);
    
        return [NSString stringWithFormat:@"%@ %@", firstName?firstName:@"", surname?surname:@""];
    }
    return nil;
}


- (NSString*) getUsernameLabelFromAddressBook {
    if (self.addressBookId && self.username) {
        ABAddressBookRef addressBook = ABAddressBookCreateWithOptions(nil, nil);
        ABRecordRef currentPerson = ABAddressBookGetPersonWithRecordID(addressBook, self.addressBookId);
        
        ABMutableMultiValueRef phoneNumbers = ABRecordCopyValue(currentPerson, kABPersonPhoneProperty);
        
        NSString *label = @"";
        
        for (CFIndex i = 0; i < ABMultiValueGetCount(phoneNumbers); i++)
        {
            CFStringRef phoneNumber, phoneNumberLabel;
            
            phoneNumberLabel = ABMultiValueCopyLabelAtIndex(phoneNumbers, i);
            phoneNumber      = ABMultiValueCopyValueAtIndex(phoneNumbers, i);
            
            NSString *number = (__bridge NSString*) phoneNumber;

            if ([[TSContactManager cleanPhoneNumber:number] isEqualToString:self.username]) {
                label = (__bridge NSString *)(ABAddressBookCopyLocalizedLabel (ABMultiValueCopyLabelAtIndex(phoneNumbers, i)));
                break;
            }
            
            CFRelease(phoneNumberLabel);
            CFRelease(phoneNumber);
        }
        
        CFRelease(addressBook);
        
        return label;
        
    } else {
        return @"";
    }
}


@end
