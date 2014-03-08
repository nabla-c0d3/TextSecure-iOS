//
//  TSKeyManager.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 12/1/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSKeyManager.h"
#import "Cryptography.h"
#import "KeychainWrapper.h"
#import "NSData+Base64.h"
#import "NSData+Conversion.h"
#import "TSStorageMasterKey.h"
#import "TSStorageError.h"

@implementation TSKeyManager

//+ (BOOL) generateCryptographyKeysForNewUser {
//  [TSKeyManager generateAndStoreIdentityKey];
//  [TSKeyManager generateAndStoreNewPreKeys:70];
//  return YES;
//}


#pragma mark Username (Phone number)

+ (BOOL) storeUsername:(NSString *)phoneNumber {
  return [KeychainWrapper createKeychainValue:phoneNumber forIdentifier:usernameTokenStorageId];
}

+ (NSString*) getUsername {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:usernameTokenStorageId];
}


#pragma mark Authentication Token
+(NSString*) generateNewAccountAuthenticationToken {
  NSMutableData* authToken = [Cryptography generateRandomBytes:16];
  NSString* authTokenPrint = [[NSData dataWithData:authToken] hexadecimalString];
  return authTokenPrint;
}

+ (BOOL) storeAuthenticationToken:(NSString*)token {
  return [KeychainWrapper createKeychainValue:token forIdentifier:authenticationTokenStorageId];
}


+ (NSString*) getAuthenticationToken {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:authenticationTokenStorageId];
}


#pragma mark Authorization Token

+ (NSString*) getAuthorizationToken {
  return [self getAuthorizationTokenFromAuthToken:[TSKeyManager getAuthenticationToken]];
}

+ (NSString*) getAuthorizationTokenFromAuthToken:(NSString*)authToken{
  NSLog(@"Username : %@ and AuthToken: %@", [TSKeyManager getUsername], [TSKeyManager getAuthenticationToken] );
  return [NSString stringWithFormat:@"%@:%@",[TSKeyManager getUsername],[TSKeyManager getAuthenticationToken]];
}


#pragma mark SignalingKey


+(NSString*) generateNewSignalingKeyToken {
  /*The signalingKey is 32 bytes of AES material (256bit AES) and 20 bytes of Hmac key material (HmacSHA1) concatenated into a 52 byte slug that is base64 encoded. */
  NSMutableData* signalingKeyToken = [Cryptography generateRandomBytes:52];
  NSString* signalingKeyTokenPrint = [[NSData dataWithData:signalingKeyToken] base64EncodedString];
  return signalingKeyTokenPrint;
  
}

+ (BOOL) storeSignalingKeyToken:(NSString*)token {
  return [KeychainWrapper createKeychainValue:token forIdentifier:signalingTokenStorageId];
}

+ (NSString*) getSignalingKeyToken {
  return [KeychainWrapper keychainStringFromMatchingIdentifier:signalingTokenStorageId];
}



#pragma mark user defaults
// Detecting if a user has a verified phone number or not can be done by looking if a phone number is stored or not.
// If a phone number is present and no basic auth key, this means that a text message with a verification code has been sent but that the user never entered it.
// If both numbers are present, we are ready to use the app.

+(void) removeAllKeychainItems{
  [KeychainWrapper deleteItemFromKeychainWithIdentifier:signalingTokenStorageId];
  [KeychainWrapper deleteItemFromKeychainWithIdentifier:usernameTokenStorageId];
  [KeychainWrapper deleteItemFromKeychainWithIdentifier:authenticationTokenStorageId];
}

+(BOOL) hasVerifiedPhoneNumber{
  return ([TSKeyManager getUsername] && [TSKeyManager getAuthenticationToken] && [TSStorageMasterKey wasStorageMasterKeyCreated]);
}



@end
