//
//  TSWaitingPushMessageDatabase.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/7/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import "TSWaitingPushMessageDatabase.h"
#import "TSStorageError.h"
#import "FilePath.h"
#import "FMDatabase.h"
#import "FMDatabaseQueue.h"



#define WAITING_PUSH_MESSAGE_DB_FILE_NAME @"TSWaitingPushMessage.db"
#define WAITING_PUSH_MESSAGE_DB_PREFERENCE @"TSWaitingPushMessageDbWasCreated"


static FMDatabaseQueue *waitingPushMessageDbQueue = nil;


@interface TSWaitingPushMessageDatabase(Private)

+(BOOL) databaseOpenWithError:(NSError **)error;

@end

@implementation TSWaitingPushMessageDatabase

#pragma mark DB creation

+(BOOL) databaseCreateWaitingPushMessageDatabaseWithError:(NSError **)error {
    // This DB is not required to be encrypted-the Push message content comes in pre-encrypted with the signaling key, and inside contents with the Axolotl ratchet
    // For very limited obfuscation of meta-data (unread message count), and to reuse the encrypted DB architecture we encrypt the entire DB itself with a key stored in user preferences.
    // The key cannot be stored somewhere accessible by password as this is designed to be deployed in the situation before the user enters her password.

    // Have we created a DB on this device already ?
    if ([[NSUserDefaults standardUserDefaults] boolForKey:WAITING_PUSH_MESSAGE_DB_PREFERENCE]) {
        if (error) {
            *error = [TSStorageError errorDatabaseAlreadyCreated];
        }
        return NO;
    }
    
    // Cleanup remnants of a previous DB
    [TSWaitingPushMessageDatabase databaseErase];

    
    // Create the DB
    __block BOOL initSuccess = NO;
    FMDatabaseQueue *dbQueue = [FMDatabaseQueue databaseQueueWithPath:[FilePath pathInDocumentsDirectory:WAITING_PUSH_MESSAGE_DB_FILE_NAME]];
    [dbQueue inDatabase: ^(FMDatabase *db) {
        
        if (![db executeUpdate:@"CREATE TABLE push_messages (message_serialized_json BLOB,timestamp DATE)"]) {
            return;
        }
        initSuccess = YES;
    }];
    if (!initSuccess) {
        if (error) {
            *error = [TSStorageError errorDatabaseCreationFailed];
        }
        // Cleanup
        [TSWaitingPushMessageDatabase databaseErase];
        return NO;
    }
    waitingPushMessageDbQueue = dbQueue;
    
    // Success - store in the preferences that the DB has been successfully created
    [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:WAITING_PUSH_MESSAGE_DB_PREFERENCE];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    return YES;
}


+(void) databaseErase {
    // Update the preferences
    [[NSUserDefaults standardUserDefaults] setBool:FALSE forKey:WAITING_PUSH_MESSAGE_DB_PREFERENCE];
    [[NSUserDefaults standardUserDefaults] synchronize];
    // Erase the DB file
    [[NSFileManager defaultManager] removeItemAtPath:[FilePath pathInDocumentsDirectory:WAITING_PUSH_MESSAGE_DB_FILE_NAME] error:nil];
}


+(BOOL) databaseWasCreated {
    return [[NSUserDefaults standardUserDefaults] boolForKey:WAITING_PUSH_MESSAGE_DB_PREFERENCE];
}



+(void) queuePush:(NSDictionary*)pushMessageJson {
    // Open the DB if it hasn't been done yet
    if (![TSWaitingPushMessageDatabase databaseOpenWithError:nil]){
        NSLog(@"The database is locked!");
        return;
    }
    
    [waitingPushMessageDbQueue inDatabase:^(FMDatabase *db) {
        [db executeUpdate:@"INSERT INTO push_messages (message_serialized_json,timestamp) VALUES (?, CURRENT_TIMESTAMP)",[NSJSONSerialization dataWithJSONObject:pushMessageJson options:kNilOptions error:nil]];
    }];
}



+(void) finishPushesQueued {
    // Open the DB if it hasn't been done yet
    if (![TSWaitingPushMessageDatabase databaseOpenWithError:nil]){
        NSLog(@"The database is locked!");
        return;
    }
    
    [waitingPushMessageDbQueue inDatabase:^(FMDatabase *db) {
        [db executeUpdate:@"DELETE FROM push_messages"];
    }];

}


+(NSArray*) getPushesInReceiptOrder {
    
    // Open the DB if it hasn't been done yet
    if (![TSWaitingPushMessageDatabase databaseOpenWithError:nil]){
        NSLog(@"The database is locked!");
        return nil;
    }
    __block NSMutableArray *pushArray = [[NSMutableArray alloc] init];
    
    [waitingPushMessageDbQueue inDatabase:^(FMDatabase *db) {
        FMResultSet  *searchInDB = [db executeQuery:[NSString stringWithFormat:@"SELECT * FROM push_messages ORDER BY timestamp ASC"]];
        while([searchInDB next]) {
            [pushArray addObject:[NSJSONSerialization JSONObjectWithData:[searchInDB dataForColumn:@"message_serialized_json"] options:kNilOptions error:nil]];
        }
        [searchInDB close];
    }];
    
    return pushArray;
    
}



#pragma mark DB access - private

+(BOOL) databaseOpenWithError:(NSError **)error {
    
    // DB was already opened
    if (waitingPushMessageDbQueue){
        return YES;
    }
    
    if (![TSWaitingPushMessageDatabase databaseWasCreated]) {
        if (error) {
            *error = [TSStorageError errorDatabaseNotCreated];
        }
        return NO;
    }
    
    waitingPushMessageDbQueue = [FMDatabaseQueue databaseQueueWithPath:[FilePath pathInDocumentsDirectory:WAITING_PUSH_MESSAGE_DB_FILE_NAME]];
    return YES;
}


@end
