//
//  TSKeyManager.h
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 12/1/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>
@class ECKeyPair;
@interface TSKeyManager : NSObject


#pragma mark username
+ (BOOL) storeUsername:(NSString*)phoneNumber;
+ (NSString*) getUsername;


#pragma mark authentication
/*
 Basic auth is username:password base64 encoded where the "username" is the device's phone number in E164 format, and the "password" is a random string you generate at registration time.
 What we're doing is just using the Authorization header to convey that information, since it's more REST-ish. In subsequent calls, you'll authenticate with the same Authorization header.
 */
+(NSString*) generateNewAccountAuthenticationToken;
+ (BOOL) storeAuthenticationToken:(NSString*)token;
+ (NSString*) getAuthenticationToken;
#pragma mark authorization
+ (NSString*) getAuthorizationToken;
+ (NSString*) getAuthorizationTokenFromAuthToken:(NSString*)authToken;

#pragma mark signalingkey

/*  The signalingKey is 32 bytes of AES material (256bit AES) and 20 bytes of Hmac key material (HmacSHA1) concatenated into a 52 byte slug that is base64 encoded.
 See   for usage, 52 random bytes generated at init which will be used as key material for AES256 (first 32 bytes) and HmacSHA1 */
+(NSString*) generateNewSignalingKeyToken;

+ (BOOL) storeSignalingKeyToken:(NSString*)token;
+ (NSString*) getSignalingKeyToken;

#pragma mark user defaults
+(void) removeAllKeychainItems;
+(BOOL) hasVerifiedPhoneNumber;


@end
