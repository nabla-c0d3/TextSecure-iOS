//
//  TSMessagesDatabase.h
//  TextSecureiOS
//
//  Created by Alban Diquet on 11/25/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSProtocols.h"

@class TSMessage;
@class TSThread;
@class TSContact;

/**
 * Posted when the database receives an update
 */
extern NSString * const TSDatabaseDidUpdateNotification;


@interface TSMessagesDatabase : NSObject<AxolotlPersistantStorage>


+(BOOL) databaseCreateWithError:(NSError **)error;
+(void) databaseErase;
+(BOOL) databaseWasCreated;


// Calling the following functions will fail if the storage master key hasn't been unlocked

#pragma mark - settings values
+(BOOL) storePersistentSettings:(NSDictionary*)settingNamesAndValues;

#pragma mark - DB message functions
+(void) storeMessage:(TSMessage*)message fromThread:(TSThread*)thread;
+(NSArray*) getMessagesOnThread:(TSThread*) thread;
+(NSArray*) getThreads;
+ (TSContact *)getContactWithUsername:(NSString *)username;
+ (void)storeContact:(TSContact *)contact;
+(void)storeTSThread:(TSThread*)thread ;

#pragma mark - AxolotlEphemeralStorage protocol getter/setter helper methods

#pragma mark - AxolotlPersistantStorage protocol getter/setter helper methods
+(NSData*) getAPSDataField:(NSString*)name onThread:(TSThread*)thread;
+(NSNumber*) getAPSIntField:(NSString*)name onThread:(TSThread*)thread;
+(BOOL) getAPSBoolField:(NSString*)name onThread:(TSThread*)thread;
+(NSString*) getAPSStringField:(NSString*)name  onThread:(TSThread*)thread;
+(NSString*) getAPSFieldName:(NSString*)name onChain:(TSChainType) chain;
/*
 parameters
 nameField : name of db field to set
 valueField : value of db field to set to
 threadID" : thread id
 */
+(void) setAPSDataField:(NSDictionary*) parameters;

@end

