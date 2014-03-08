//
//  TSMessagesDatabase.m
//  TextSecureiOS
//
//  Created by Alban Diquet on 11/25/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSMessagesDatabase.h"
#import "TSStorageError.h"
#import <FMDB/FMDatabase.h>
#import <FMDB/FMDatabaseQueue.h>

#import "FilePath.h"
#import "TSMessage.h"
#import "TSContact.h"
#import "TSThread.h"
#import "TSAttachment.h"
#import "TSStorageMasterKey.h"
#import "TSEncryptedDatabase.h"
#import "TSKeyManager.h"

#define kDBWasCreatedBool @"TSMessagesWasCreated"
#define databaseFileName @"TSMessages.db"


NSString * const TSDatabaseDidUpdateNotification = @"com.whispersystems.database.update";


// Reference to the singleton
static TSEncryptedDatabase *messagesDb = nil;


@interface TSMessagesDatabase(Private)

+(BOOL) databaseOpenWithError:(NSError **)error;

@end


@implementation TSMessagesDatabase

#pragma mark DB creation

+(BOOL) databaseCreateWithError:(NSError **)error {
    
    // Create the database
    TSEncryptedDatabase *db = [TSEncryptedDatabase  databaseCreateAtFilePath:[FilePath pathInDocumentsDirectory:databaseFileName] updateBoolPreference:kDBWasCreatedBool error:error];
    if (!db) {
        return NO;
    }
    
    
    // Create the tables we need
    __block BOOL dbInitSuccess = NO;
    [db.dbQueue inDatabase:^(FMDatabase *db) {
        if (![db executeUpdate:@"CREATE TABLE persistent_settings (setting_name TEXT UNIQUE,setting_value TEXT)"]) {
            // Happens when the master key is wrong (ie. wrong (old?) encrypted key in the keychain)
            return;
        }
        if (![db executeUpdate:@"CREATE TABLE personal_prekeys (prekey_id INTEGER UNIQUE,public_key TEXT,private_key TEXT, last_counter INTEGER)"]){
            return;
        }
#warning we will want a subtler format than this, prototype message db format
        
        /*
         RK           : 32-byte root key which gets updated by DH ratchet
         HKs, HKr     : 32-byte header keys (send and recv versions)
         NHKs, NHKr   : 32-byte next header keys (")
         CKs, CKr     : 32-byte chain keys (used for forward-secrecy updating)
         DHIs, DHIr   : DH or ECDH Identity keys
         DHRs, DHRr   : DH or ECDH Ratchet keys
         Ns, Nr       : Message numbers (reset to 0 with each new ratchet)
         PNs          : Previous message numbers (# of msgs sent under prev ratchet)
         ratchet_flag : True if the party will send a new DH ratchet key in next msg
         skipped_HK_MK : A list of stored message keys and their associated header keys
         for "skipped" messages, i.e. messages that have not been
         received despite the reception of more recent messages.
         Entries may be stored with a timestamp, and deleted after a
         certain age.
         */
        
        
        if (![db executeUpdate:@"CREATE TABLE IF NOT EXISTS threads (thread_id TEXT PRIMARY KEY, rk BLOB, cks BLOB, ckr BLOB, dhis BLOB, dhir BLOB, dhrs BLOB, dhrr BLOB, ns INT, nr INT, pns INT)"]) {
            return;
        }
        if (![db executeUpdate:@"CREATE TABLE IF NOT EXISTS missed_messages (skipped_MK BLOB,skipped_HKs BLOB, skipped_HKr BLOB,thread_id TEXT,FOREIGN KEY(thread_id) REFERENCES threads(thread_id))"]) {
            return;
        }
        
        if (![db executeUpdate:@"CREATE TABLE IF NOT EXISTS messages (message_id INT PRIMARY KEY,message TEXT,thread_id TEXT,sender_id TEXT,recipient_id TEXT, timestamp DATE,FOREIGN KEY(thread_id) REFERENCES threads(thread_id))"]) {
            return;
        }
        
        if (![db executeUpdate:@"CREATE TABLE IF NOT EXISTS contacts (username TEXT, relay TEXT, addressBookId INTEGER, identityKey TEXT, isIdentityKeyVerified INTEGER, supportsSMS INTEGER, nextKey TEXT)"]){
            return;
        }
        
        dbInitSuccess = YES;
        
    }];
    
    if (!dbInitSuccess) {
        if (error) {
            *error = [TSStorageError errorDatabaseCreationFailed];
        }
        // Cleanup
        [TSMessagesDatabase databaseErase];
        return NO;
    }
    
    messagesDb = db;
    return YES;
}


+(void) databaseErase {
    [TSEncryptedDatabase databaseEraseAtFilePath:[FilePath pathInDocumentsDirectory:databaseFileName] updateBoolPreference:kDBWasCreatedBool];
}


+(BOOL) databaseOpenWithError:(NSError **)error {
    
    // DB was already unlocked
    if (messagesDb){
        return YES;
    }
    
    if (![TSMessagesDatabase databaseWasCreated]) {
        if (error) {
            *error = [TSStorageError errorDatabaseNotCreated];
        }
        return NO;
    }
    
    messagesDb = [TSEncryptedDatabase databaseOpenAndDecryptAtFilePath:[FilePath pathInDocumentsDirectory:databaseFileName] error:error];
    if (!messagesDb) {
        return NO;
    }
    return YES;
}


+(BOOL) storePersistentSettings:(NSDictionary*)settingNamesAndValues {
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return NO;
    }
    
    __block BOOL updateSuccess = YES;
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        for(id settingName in settingNamesAndValues) {
            if (![db executeUpdate:@"INSERT OR REPLACE INTO persistent_settings (setting_name,setting_value) VALUES (?, ?)",settingName,[settingNamesAndValues objectForKey:settingName]]) {
                DLog(@"Error updating DB: %@", [db lastErrorMessage]);
                updateSuccess = NO;
            }
        }
    }];
    return updateSuccess;
}


#pragma mark Database state

+(BOOL) databaseWasCreated {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kDBWasCreatedBool];
}


#pragma mark - DB message methods

+(void) storeMessage:(TSMessage*)message fromThread:(TSThread*) thread {
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil]) {
            // TODO: better error handling
            return;
        }
    }
    
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        NSDateFormatter *dateFormatter = [[self class] sharedDateFormatter];
        NSString *sqlDate = [dateFormatter stringFromDate:message.timestamp];
        [db executeUpdate:@"INSERT OR REPLACE INTO threads (thread_id) VALUES (?)",thread.threadID];
        [db executeUpdate:@"INSERT INTO messages (message,thread_id,sender_id,recipient_id,timestamp) VALUES (?, ?, ?, ?, ?)",message.content,thread.threadID,message.senderId,message.recipientId,sqlDate];
        
    }];
}

+(NSArray*) getMessagesOnThread:(TSThread*) thread {
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return nil;
    }
    
    __block NSMutableArray *messageArray = [[NSMutableArray alloc] init];
    // debug why this is returning me, and then you separately.
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        NSDateFormatter *dateFormatter = [[self class] sharedDateFormatter];
        FMResultSet  *searchInDB = [db executeQuery:[NSString stringWithFormat:@"SELECT * FROM messages WHERE thread_id=\"%@\" ORDER BY timestamp", [thread threadID]]];
        
        while([searchInDB next]) {
            NSString* timestamp = [searchInDB stringForColumn:@"timestamp"];
            NSDate *date = [dateFormatter dateFromString:timestamp];
            TSAttachment *attachment = nil;
            TSAttachmentType attachmentType = [searchInDB intForColumn:@"attachment_type"];
            if(attachmentType!=TSAttachmentEmpty) {
                NSString *attachmentDataPath = [searchInDB stringForColumn:@"attachment"];
                NSData *attachmentDecryptionKey = [searchInDB dataForColumn:@"attachment_decryption_key"];
                attachment = [[TSAttachment alloc] initWithAttachmentDataPath:attachmentDataPath withType:attachmentType withDecryptionKey:attachmentDecryptionKey];
            }
            [messageArray addObject:[TSMessage messageWithContent:[searchInDB stringForColumn:@"message"] sender:[searchInDB stringForColumn:@"sender_id"] recipient:[searchInDB stringForColumn:@"recipient_id"] date:date attachment:attachment]];
        }
    }];
    
    
    return messageArray;
}

// This is only a temporary stub for fetching the message threads
// TODO: return the threads containing participants as well
+(NSArray *) getThreads {
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return nil;
    }
    
    __block NSMutableArray *threadArray = [[NSMutableArray alloc] init];
    
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        NSDateFormatter *dateFormatter = [[self class] sharedDateFormatter];
        FMResultSet  *searchInDB = [db executeQuery:@"SELECT *,MAX(m.timestamp) FROM messages m GROUP BY thread_id ORDER BY timestamp DESC;"];
        
        while([searchInDB next]) {
            NSString* timestamp = [searchInDB stringForColumn:@"timestamp"];
            NSDate *date = [dateFormatter dateFromString:timestamp];
            
            // TODO: fetch threads from the threads DB table directly as the current implementation will fail for group message
            NSString *senderUsername = [searchInDB stringForColumn:@"sender_id"];
            NSString *receiverUsername = [searchInDB stringForColumn:@"recipient_id"];
            NSString *contactUsername;
            
            
            if ([[TSKeyManager getUsername] isEqualToString:receiverUsername]) {
                contactUsername = senderUsername;
            }
            else {
                contactUsername = receiverUsername;
            }
            TSThread *messageThread = [TSThread threadWithContact:contactUsername];
            
            TSAttachment *attachment = nil;
            TSAttachmentType attachmentType = [searchInDB intForColumn:@"attachment_type"];
            if(attachmentType!=TSAttachmentEmpty) {
                NSString *attachmentDataPath = [searchInDB stringForColumn:@"attachment"];
                NSData *attachmentDecryptionKey = [searchInDB dataForColumn:@"attachment_decryption_key"];
                attachment = [[TSAttachment alloc] initWithAttachmentDataPath:attachmentDataPath withType:attachmentType withDecryptionKey:attachmentDecryptionKey];
            }
            
            messageThread.latestMessage = [TSMessage messageWithContent:[searchInDB stringForColumn:@"message"]
                                                                 sender:senderUsername
                                                              recipient:receiverUsername
                                                                   date:date];
            
            [threadArray addObject:messageThread];
        }
        [searchInDB close];
    }];
    
    return threadArray;
}

+(void)storeTSThread:(TSThread*)thread {
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return;
    }
    
    
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        for(TSContact* contact in thread.participants) {
            //TODO: Get rid of the save method
           // [contact save];
        }
    }];
}

+ (TSContact *)getContactWithUsername:(NSString *)username{
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return nil;
    }
    
    __block TSContact *contact = nil;
    
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchInDB = [db executeQuery:@"SELECT username FROM contacts WHERE username = :username " withParameterDictionary:@{@"username":username}];
        
        if ([searchInDB next]) {
            contact = [TSContact contactWithUsername:[searchInDB stringForColumn:@"username"]
                                       addressBookId:[searchInDB intForColumn:@"addressBookId"]
                                               relay:[searchInDB stringForColumn:@"relay"]
                                         supportsSMS:[searchInDB boolForColumn:@"supportsSMS"]
                                             nextKey:[searchInDB stringForColumn:@"nextKey"]
                                         identityKey:[searchInDB stringForColumn:@"identityKey"]
                               isIdentityKeyVerified:[searchInDB boolForColumn:@"isIdentityKeyVerified"]];
        }
        
        [searchInDB close];
    }];
    
    return contact;
}


+(void)storeContact:(TSContact *)contact {
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return;
    }
    
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchInDB = [db executeQuery:@"SELECT username FROM contacts WHERE username = :phoneNumber " withParameterDictionary:@{@"phoneNumber":contact.username}];
        
        NSDictionary *parameterDictionary = @{@"username": contact.username, @"relay": contact.relay, @"addressBookId": [NSNumber numberWithInt: contact.addressBookId], @"identityKey": contact.identityKey, @"identityKeyIsVerified":contact.isIdentityKeyVerified, @"supportsSMS":contact.supportsSMS, @"nextKey":contact.nextKey};
        
        
        if ([searchInDB next]) {
            // the phone number was found, let's now update the contact
            [db executeUpdate:@"UPDATE contacts SET relay = :relay, addressBookId :addressBookId, identityKey = :identityKey, isIdentityKeyVerified = :isIdentityKeyVerified, supportsSMS = :supportsSMS, nextKey = :nextKey WHERE username = :username" withParameterDictionary:parameterDictionary];
        }
        else{
            // the contact doesn't exist, let's create him
            [db executeUpdate:@"REPLACE INTO contacts (:username,:relay , :addressBookId, :identityKey, :identityKeyIsVerified, :supportsSMS, :nextKey)" withParameterDictionary:parameterDictionary];
        }
        [searchInDB close];
    }];
    
}

#pragma mark - AxolotlPersistantStorage protocol getter/setter helper methods

+(NSData*) getAPSDataField:(NSString*)name onThread:(TSThread*)thread{
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil]) {
            // TODO: better error handling
            return nil;
        }
    }
    __block NSData* apsField = nil;
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchInDB = [db executeQuery:@"SELECT * FROM threads WHERE thread_id = :threadID " withParameterDictionary:@{@"threadID":thread.threadID}];
        if ([searchInDB next]) {
            apsField= [searchInDB dataForColumn:name];
        }
        [searchInDB close];
    }];
    return apsField;
}


+(NSNumber*) getAPSIntField:(NSString*)name onThread:(TSThread*)thread {
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil]) {
            // TODO: better error handling
            return 0;
        }
    }
    __block NSNumber* apsField = 0;
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchInDB = [db executeQuery:@"SELECT * FROM threads WHERE thread_id = :threadID " withParameterDictionary:@{@"threadID":thread.threadID}];
        if ([searchInDB next]) {
            
            apsField= [NSNumber numberWithInt:[searchInDB intForColumn:name]];
        }
        [searchInDB close];
    }];
    return apsField;
    
}

+(BOOL) getAPSBoolField:(NSString*)name onThread:(TSThread*)thread {
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil]) {
            // TODO: better error handling
            return 0;
        }
    }
    __block int apsField = 0;
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchInDB = [db executeQuery:@"SELECT * FROM threads WHERE thread_id = :threadID " withParameterDictionary:@{@"threadID":thread.threadID}];
        if ([searchInDB next]) {
            apsField= [searchInDB boolForColumn:name];
        }
        [searchInDB close];
    }];
    return apsField;
    
}

+(NSString*) getAPSStringField:(NSString*)name onThread:(TSThread*)thread {
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil]) {
            // TODO: better error handling
            return @"";
        }
    }
    __block NSString* apsField = 0;
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        
        FMResultSet *searchInDB = [db executeQuery:@"SELECT * FROM threads WHERE thread_id = :threadID " withParameterDictionary:@{@"threadID":thread.threadID}];
        if ([searchInDB next]) {
            apsField= [searchInDB stringForColumn:name];
        }
        [searchInDB close];
    }];
    return apsField;
    
}

+(void) setAPSDataField:(NSDictionary*) parameters {
    /*
     parameters
     nameField : name of db field to set
     valueField : value of db field to set to
     threadID" : thread id
     */
    
    // Decrypt the DB if it hasn't been done yet
    if (!messagesDb) {
        if (![TSMessagesDatabase databaseOpenWithError:nil])
            // TODO: better error handling
            return;
    }
    
    [messagesDb.dbQueue inDatabase:^(FMDatabase *db) {
        //    UPDATE threads SET
        NSString* query = [NSString stringWithFormat:@"INSERT OR REPLACE INTO threads (thread_id,%@) VALUES (\"%@\",%@)",[parameters objectForKey:@"nameField"],[parameters objectForKey:@"threadID"],[parameters objectForKey:@"valueField"]];
        NSLog(@"query %@ with parameters %@",query,parameters);
        FMResultSet *rs = [db executeQuery:query withParameterDictionary:parameters];
        [rs close];
    }];
    
}

+(NSString*) getAPSFieldName:(NSString*)name onChain:(TSChainType)chain {
    switch (chain) {
        case TSReceivingChain:
            return [name stringByAppendingString:@"r"];
            break;
        case TSSendingChain:
            return [name stringByAppendingString:@"s"];
        default:
            return name;
            break;
    }
}


#pragma mark - AxolotlPersistantStorage protocol methods

/* Axolotl Protocol variables. Persistant storage per thread */
/* Root key*/
+(NSData*) getRK:(TSThread*)thread {
    return [TSMessagesDatabase getAPSDataField:@"rk"  onThread:thread];
}


+(void) setRK:(NSData*)key onThread:(TSThread*)thread {
    [TSMessagesDatabase setAPSDataField:@{@"nameField":@"rk",@"valueField":key,@"threadID":thread.threadID}];
}
/* Chain keys */
+(NSData*) getCK:(TSThread*)thread onChain:(TSChainType)chain{
    return [TSMessagesDatabase getAPSDataField:[TSMessagesDatabase getAPSFieldName:@"ck" onChain:chain] onThread:thread];
    
}
+(void) setCK:(NSData*)key onThread:(TSThread*)thread onChain:(TSChainType)chain{
    [TSMessagesDatabase setAPSDataField:@{@"nameField":[TSMessagesDatabase getAPSFieldName:@"rk" onChain:chain],@"valueField":key,@"threadID":thread.threadID}];
}

/* ephemeral keys of chains */
+(NSData*) getEphemeralOfReceivingChain:(TSThread*)thread {
    return [TSMessagesDatabase getAPSDataField:[TSMessagesDatabase getAPSFieldName:@"dhr" onChain:TSReceivingChain ] onThread:thread];
    
}

+(void) setEphemeralOfReceivingChain:(NSData*)key onThread:(TSThread*)thread {
    [TSMessagesDatabase setAPSDataField:@{@"nameField":[TSMessagesDatabase getAPSFieldName:@"dhr" onChain:TSReceivingChain],@"valueField":key,@"threadID":thread.threadID}];
}

+(TSECKeyPair*) getEphemeralOfSendingChain:(TSThread*)thread {
    return [NSKeyedUnarchiver unarchiveObjectWithData:[TSMessagesDatabase getAPSDataField:[TSMessagesDatabase getAPSFieldName:@"dhr" onChain:TSSendingChain ] onThread:thread]];
}

+(void) setEphemeralOfSendingChain:(TSECKeyPair*)key onThread:(TSThread*)thread {
    [TSMessagesDatabase setAPSDataField:@{@"nameField":[TSMessagesDatabase getAPSFieldName:@"dhr" onChain:TSSendingChain],@"valueField":[NSKeyedArchiver archivedDataWithRootObject:key],@"threadID":thread.threadID}];
}






/* number of messages sent on chains */
+(NSNumber*) getN:(TSThread*)thread onChain:(TSChainType)chain{
    return [TSMessagesDatabase getAPSIntField:[TSMessagesDatabase getAPSFieldName:@"n" onChain:chain] onThread:thread];
    
}
+(void) setN:(NSNumber*)num onThread:(TSThread*)thread onChain:(TSChainType)chain{
    [TSMessagesDatabase setAPSDataField:@{@"nameField":[TSMessagesDatabase getAPSFieldName:@"n" onChain:chain],@"valueField":num,@"threadID":thread.threadID}];
}

/* number of messages sent on the last chain */
+(NSNumber*)getPNs:(TSThread*)thread{
    return [TSMessagesDatabase getAPSIntField:@"pns" onThread:thread];
}
+(void)setPNs:(NSNumber*)num onThread:(TSThread*)thread{
    [TSMessagesDatabase setAPSDataField:@{@"nameField":@"pns",@"valueField":num,@"threadID":thread.threadID}];
}

//Ns, Nr       : sets N to N+1 returns value of N prior to setting,  Message numbers (reset to 0 with each new ratchet)
+(NSNumber*) getNPlusPlus:(TSThread*)thread onChain:(TSChainType)chain {
    NSNumber* N = [TSMessagesDatabase getN:thread onChain:chain];
    
    [TSMessagesDatabase setN:[NSNumber numberWithInt:[N integerValue]+1] onThread:thread onChain:chain];
    return N;
    
}

#pragma mark - shared private objects

+ (NSDateFormatter *)sharedDateFormatter {
    static NSDateFormatter *_sharedFormatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedFormatter = [[NSDateFormatter alloc] init];
        _sharedFormatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
        _sharedFormatter.timeZone = [NSTimeZone localTimeZone];
    });
    
    return _sharedFormatter;
}

@end
