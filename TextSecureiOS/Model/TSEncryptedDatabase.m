//
//  TSEncryptedDatabase.m
//  TextSecureiOS
//
//  Created by Alban Diquet on 12/29/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSEncryptedDatabase.h"
#import "FMDatabaseQueue.h"
#import "FMDatabase.h"
#import "TSStorageError.h"
#import "TSStorageMasterKey.h"


@interface TSEncryptedDatabase(Private)

-(instancetype) initWithDatabaseQueue:(FMDatabaseQueue *)queue;

@end

extern NSString * const TSDatabaseDidUnlockNotification;


@implementation TSEncryptedDatabase {
}


+(instancetype) databaseCreateAtFilePath:(NSString *)dbFilePath updateBoolPreference:(NSString *)preferenceName error:(NSError **)error {

    // Have we created a DB on this device already ?
    if ([[NSUserDefaults standardUserDefaults] boolForKey:preferenceName]) {
        if (error) {
            *error = [TSStorageError errorDatabaseAlreadyCreated];
        }
        return nil;
    }
    
    // Cleanup remnants of a previous DB
    [TSEncryptedDatabase databaseEraseAtFilePath:dbFilePath updateBoolPreference:preferenceName];
    
    // Create the DB
    TSEncryptedDatabase *encryptedDb = [[TSEncryptedDatabase alloc] initWithFilePath:dbFilePath];
    if (![encryptedDb openAndDecrypt:error]) {
        // Cleanup
        [TSEncryptedDatabase databaseEraseAtFilePath:dbFilePath updateBoolPreference:preferenceName];
        return nil;
    }
    
    
    // Success - store in the preferences that the DB has been successfully created
    [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:preferenceName];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    return encryptedDb;
}


+(instancetype) databaseOpenAndDecryptAtFilePath:(NSString *)dbFilePath error:(NSError **)error {
    
    TSEncryptedDatabase *encryptedDb = [[TSEncryptedDatabase alloc] initWithFilePath:dbFilePath];
    if (![encryptedDb openAndDecrypt:error]) {
        return nil;
    }

    return encryptedDb;
}


+(void) databaseEraseAtFilePath:(NSString *)dbFilePath updateBoolPreference:(NSString *)preferenceName {
    // Update the preferences
    [[NSUserDefaults standardUserDefaults] setBool:FALSE forKey:preferenceName];
    [[NSUserDefaults standardUserDefaults] synchronize];
    // Erase the DB file
    [[NSFileManager defaultManager] removeItemAtPath:dbFilePath error:nil];
}


-(instancetype) initWithFilePath:(NSString *)dbFilePath {
    if(self=[super init]) {
        self->_dbFilePath = dbFilePath;
        self->_dbQueue = nil;
    }
    

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(masterStorageKeyWasUnlocked:)
                                                 name:TSStorageMasterKeyWasUnlockedNotification
                                               object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(masterStorageKeyWasLocked:)
                                                 name:TSStorageMasterKeyWasLockedNotification
                                               object:nil];
    
    return self;
}


- (void) dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}


-(BOOL) openAndDecrypt:(NSError **)error {
    
    // Get the storage master key
    NSData *storageKey = [TSStorageMasterKey getStorageMasterKeyWithError:error];
    if (!storageKey) {
        return NO;
    }
    
    // Try to open the DB
    __block BOOL initSuccess = NO;
    FMDatabaseQueue *dbQueue = [FMDatabaseQueue databaseQueueWithPath:self.dbFilePath];
    
    [dbQueue inDatabase:^(FMDatabase *db) {
        if(![db setKeyWithData:storageKey]) {
            // Supplied password was valid but the master key wasn't
            return;
        }
        // Do a test query to make sure the DB is available
        // if this throws an error, the key was incorrect. If it succeeds and returns a numeric value, the key is correct;
        FMResultSet *rset = [db executeQuery:@"SELECT count(*) FROM sqlite_master"];
        if (rset) {
            [rset close];
            initSuccess = YES;
            return;
        }}];
    
    if (!initSuccess) {
        if (error) {
            *error = [TSStorageError errorStorageKeyCorrupted];
        }
        return NO;
    }
    
    self->_dbQueue = dbQueue;
    return YES;
}


-(void) masterStorageKeyWasUnlocked:(NSNotification *)note {
    // Use the storage key to decrypt the DB
    // This should never fail
    if (![self openAndDecrypt:nil]){
        @throw [NSException exceptionWithName:@"database corrupted" reason:@"unable to unlock to the database" userInfo:nil];
    }
}


-(void) masterStorageKeyWasLocked:(NSNotification *)note {
    // Discard the DB handle
    self->_dbQueue = nil;
}



@end
