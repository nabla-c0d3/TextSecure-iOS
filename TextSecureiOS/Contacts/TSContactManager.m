//
//  TSContactManager.m
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 10/12/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSContactManager.h"
#import <NBPhoneNumberUtil.h>
#import <NBPhoneNumber.h>
#import <AddressBook/AddressBook.h>
#import "NSString+Conversion.h"
#import "Cryptography.h"
#import "TSNetworkManager.h"
#import "TSMessagesDatabase.h"
#import "TSContactsIntersectionRequest.h"

@implementation TSContactManager

+ (id)sharedManager {
    static TSContactManager *sharedMyManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedMyManager = [[self alloc] init];
    });
    
    return sharedMyManager;
}

- (id)init {
    if (self = [super init]) {
        
    }
    return self;
}

/**
 *  Returns a given phone number in international E.123 format but without any white-spaces
 *
 *  @param number phone number to convert to E.123
 */

+ (NSString*) cleanPhoneNumber:(NSString*)number{
    NBPhoneNumberUtil *phoneUtil = [NBPhoneNumberUtil sharedInstance];
    
    NBPhoneNumber *phone = [phoneUtil parse:number defaultRegion:[[NSLocale currentLocale]objectForKey:NSLocaleCountryCode] error:nil];
    return [NSString stringWithFormat:@"+%i%llu", (unsigned)phone.countryCode, phone.nationalNumber];
}

+ (void) getAllContactsIDs:(void (^)(NSArray *contacts))contactFetchCompletionBlock{
    
    ABAddressBookRef addressBook = ABAddressBookCreateWithOptions(NULL, nil);
    
    __block BOOL accessGranted = NO;
    
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    ABAddressBookRequestAccessWithCompletion(addressBook, ^(bool granted, CFErrorRef error) {
        accessGranted = granted;
        dispatch_semaphore_signal(sema);
    });
    
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    
    if (accessGranted) {
        CFArrayRef all = ABAddressBookCopyArrayOfAllPeople(addressBook);
        CFIndex n = ABAddressBookGetPersonCount(addressBook);
        NSMutableDictionary *hashedAB = [NSMutableDictionary dictionary];
        NSMutableDictionary *originalAB = [NSMutableDictionary dictionary];
        
        for( int i = 0 ; i < n ; i++ )
        {
            ABRecordRef ref = CFArrayGetValueAtIndex(all, i);
            int referenceID = ABRecordGetRecordID(ref);
            NSNumber *contactReferenceID = [NSNumber numberWithInt:referenceID];
            // We iterate through users
            
            ABMultiValueRef phones = ABRecordCopyValue(ref, kABPersonPhoneProperty);
            for(CFIndex j = 0; j < ABMultiValueGetCount(phones); j++)
            {
                CFStringRef phoneNumberRef = ABMultiValueCopyValueAtIndex(phones, j);
                NSString *phoneNumber = (__bridge NSString *)phoneNumberRef;
                
                NSString *cleanedNumber = [self cleanPhoneNumber:phoneNumber];
                NSString *hashedPhoneNumber = [Cryptography truncatedSHA1Base64EncodedWithoutPadding:cleanedNumber];
                
                [hashedAB setObject:contactReferenceID forKey:hashedPhoneNumber];
                [originalAB setObject:cleanedNumber forKey:hashedPhoneNumber];
            }
        }
        
        // Send hashes to server
        
        [[TSNetworkManager sharedManager]queueAuthenticatedRequest:[[TSContactsIntersectionRequest alloc] initWithHashesArray:[hashedAB allKeys]] success:^(AFHTTPRequestOperation *operation, id responseObject) {
            NSArray *contactsHashes = [responseObject objectForKey:@"contacts"];
            
            NSMutableArray *contacts = [NSMutableArray array];
            
            for (NSDictionary *contactHash in contactsHashes) {
                TSContact *contact = [TSContact contactWithUsername:[originalAB objectForKey:[contactHash objectForKey:@"token"]]
                                                      addressBookId:[[hashedAB objectForKey:[contactHash objectForKey:@"token"]] intValue]];
                [contacts addObject:contact];
            }
            
            // Store contacts in DB
            for (TSContact *contact in contacts) {
                [TSMessagesDatabase storeContact:contact];
            }
            
            contactFetchCompletionBlock(contacts);
            
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            
            defaultNetworkErrorMessage
            
        }];
        
    }
}

- (void)dealloc {
    // Should never be called, but just here for clarity really.
}

@end
