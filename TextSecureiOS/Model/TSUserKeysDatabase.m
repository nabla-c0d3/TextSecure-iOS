//
//  TSUserKeysDatabase.m
//  TextSecureiOS
//
//  Created by Alban Diquet on 12/29/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSUserKeysDatabase.h"
#import "TSEncryptedDatabase.h"
#import "TSStorageError.h"
#import "TSECKeyPair.h"
#import "FilePath.h"
#import "FMDatabase.h"
#import "FMDatabaseQueue.h"

#define PREKEYS_NUMBER 70

#define USER_KEYS_DB_FILE_NAME @"TSUserKeys.db"
#define USER_KEYS_DB_PREFERENCE @"TSUserKeysDbWasCreated"


static TSEncryptedDatabase *userKeysDb = nil;


@interface TSUserKeysDatabase(Private)

+(BOOL) databaseOpenWithError:(NSError **)error;
+(BOOL) generateAndStorePreKeys;
+(BOOL) generateAndStoreIdentityKey;

@end


@implementation TSUserKeysDatabase

#pragma mark DB creation

+(BOOL) databaseCreateUserKeysWithError:(NSError **)error {
    
    // Create the database
    TSEncryptedDatabase *db = [TSEncryptedDatabase  databaseCreateAtFilePath:[FilePath pathInDocumentsDirectory:USER_KEYS_DB_FILE_NAME] updateBoolPreference:USER_KEYS_DB_PREFERENCE error:error];
    if (!db) {
        return NO;
    }
    
    
    // Create the tables we need
    userKeysDb = db;
    __block BOOL querySuccess = NO;
    [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
        
        if (![db executeUpdate:@"CREATE TABLE user_identity_key (serialized_keypair BLOB)"]) {
            return;
        }
        if (![db executeUpdate:@"CREATE TABLE user_prekeys (prekey_id INTEGER UNIQUE, serialized_keypair BLOB)"]){
            return;
        }
        
        querySuccess = YES;
    }];
    if (!querySuccess) {
        if (error) {
            *error = [TSStorageError errorDatabaseCreationFailed];
        }
        // Cleanup
        [TSUserKeysDatabase databaseErase];
        userKeysDb = nil;
        return NO;
    }
    
    
    // Generate and store the TextSecure keys for the current user
    if (!([TSUserKeysDatabase generateAndStorePreKeys] && ([TSUserKeysDatabase generateAndStoreIdentityKey]))) {
        if (error) {
            *error = [TSStorageError errorDatabaseCreationFailed];
        }
        // Cleanup
        [TSUserKeysDatabase databaseErase];
        userKeysDb = nil;
        return NO;
    };
    
    
    return YES;
}


+(void) databaseErase {
    [TSEncryptedDatabase databaseEraseAtFilePath:[FilePath pathInDocumentsDirectory:USER_KEYS_DB_FILE_NAME] updateBoolPreference:USER_KEYS_DB_PREFERENCE];
}


+(BOOL) databaseWasCreated {
    return [[NSUserDefaults standardUserDefaults] boolForKey:USER_KEYS_DB_PREFERENCE];
}


#pragma mark DB access - private

+(BOOL) databaseOpenWithError:(NSError **)error {
    
    // DB was already unlocked
    if (userKeysDb){
        return YES;
    }
    
    if (![TSUserKeysDatabase databaseWasCreated]) {
        if (error) {
            *error = [TSStorageError errorDatabaseNotCreated];
        }
        return NO;
    }
    
    TSEncryptedDatabase *db = [TSEncryptedDatabase databaseOpenAndDecryptAtFilePath:[FilePath pathInDocumentsDirectory:USER_KEYS_DB_FILE_NAME] error:error];
    if (!db) {
        return NO;
    }
    userKeysDb = db;
    return YES;
}


#pragma Keys access

+(TSECKeyPair*) identityKeyWithError:(NSError **)error {
    
    // Decrypt the DB if it hasn't been done yet
    if (![TSUserKeysDatabase databaseOpenWithError:error]){
        return nil;
    }
    
    // Fetch the key from the DB
    __block NSData *serializedKeyPair = nil;
    [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
        FMResultSet *rs = [db executeQuery:@"SELECT serialized_keypair FROM user_identity_key"];
        if([rs next]) {
            serializedKeyPair = [rs dataForColumn:@"serialized_keypair"];
        }
        [rs close];
    }];
    return [NSKeyedUnarchiver unarchiveObjectWithData:serializedKeyPair];
}


+(NSArray *)allPreKeysWithError:(NSError **)error {
    
    // Decrypt the DB if it hasn't been done yet
    if (![TSUserKeysDatabase databaseOpenWithError:error]){
        return nil;
    }
    
    // Fetch all keys from the DB
    __block NSMutableArray *preKeys = [NSMutableArray arrayWithCapacity:PREKEYS_NUMBER];
    __block int preKeysNb = 0;
    
    [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
        FMResultSet *rs = [db executeQuery:@"SELECT serialized_keypair FROM user_prekeys"];
        while([rs next]) {
            preKeysNb++;
            NSData *serializedKeyPair = [rs dataForColumn:@"serialized_keypair"];
            [preKeys addObject:[NSKeyedUnarchiver unarchiveObjectWithData:serializedKeyPair]];
        }
        [rs close];
    }];
    if (preKeysNb != PREKEYS_NUMBER+1) {
        if (error) {
            *error = [TSStorageError errorDatabaseCorrupted];
        }
        return nil;
    }
    
    return preKeys;
}


+(TSECKeyPair*) preKeyWithId:(int32_t)preKeyId error:(NSError **)error {
    
    // Decrypt the DB if it hasn't been done yet
    if (![TSUserKeysDatabase databaseOpenWithError:error]){
        return nil;
    }
    
    // Fetch the key from the DB
    __block NSData *serializedKeyPair = nil;
    [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
        FMResultSet *rs = [db executeQuery:[NSString stringWithFormat:@"SELECT serialized_keypair FROM user_prekeys WHERE prekey_id=%d", preKeyId]];
        if([rs next]) {
            serializedKeyPair = [rs dataForColumn:@"serialized_keypair"];
        }
        [rs close];
    }];
    if (!serializedKeyPair) {
        if (error) {
            *error = [TSStorageError errorDatabaseCorrupted];
        }
        return nil;
    }
    
    return [NSKeyedUnarchiver unarchiveObjectWithData:serializedKeyPair];
}


#pragma mark User keys generation - private

+(BOOL) generateAndStoreIdentityKey {
    /*
     An identity key is an ECC key pair that you generate at install time. It never changes, and is used to certify your identity (clients remember it whenever they see it communicated from other clients and ensure that it's always the same).
     
     In secure protocols, identity keys generally never actually encrypt anything, so it doesn't affect previous confidentiality if they are compromised. The typical relationship is that you have a long term identity key pair which is used to sign ephemeral keys (like the prekeys).
     */
    
    NSData *serializedKey  = [NSKeyedArchiver archivedDataWithRootObject:[TSECKeyPair keyPairGenerateWithPreKeyId:0]];
    
    __block BOOL updateSuccess;
    [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
        if ([db executeUpdate:@"INSERT INTO user_identity_key (serialized_keypair) VALUES (?)", serializedKey]) {
            updateSuccess = YES;
        }
    }];
    if (!updateSuccess) {
        return NO;
    }
    return YES;
}

+(BOOL) generateAndStorePreKeys {
    
    // Generate and store key of last resort
    NSData *serializedPreKey  = [NSKeyedArchiver archivedDataWithRootObject:[TSECKeyPair keyPairGenerateWithPreKeyId:0xFFFFFF]];
    
    __block BOOL updateSuccess;
    [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
        if ([db executeUpdate:@"INSERT INTO user_prekeys (prekey_id, serialized_keypair) VALUES (?,?)",[NSNumber numberWithInt:0xFFFFFF], serializedPreKey]) {
            updateSuccess = YES;
        }
    }];
    if (!updateSuccess) {
        return NO;
    }
    
    // Generate and store other pre keys
    int prekeyCounter = arc4random() % 0xFFFFFF;
    
    for(int i=0; i<PREKEYS_NUMBER; i++) {
        prekeyCounter++;
        serializedPreKey = [NSKeyedArchiver archivedDataWithRootObject:[TSECKeyPair keyPairGenerateWithPreKeyId:prekeyCounter]];
        
        __block BOOL updateSuccess;
        [userKeysDb.dbQueue inDatabase: ^(FMDatabase *db) {
            if ([db executeUpdate:@"INSERT INTO user_prekeys (prekey_id, serialized_keypair) VALUES (?,?)",[NSNumber numberWithInt:prekeyCounter], serializedPreKey]) {
                updateSuccess = YES;
            }
        }];
        if (!updateSuccess) {
            return NO;
        }
    }
    return YES;
}

@end
