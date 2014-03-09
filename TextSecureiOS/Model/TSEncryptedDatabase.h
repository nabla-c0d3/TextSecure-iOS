//
//  TSEncryptedDatabase.h
//  TextSecureiOS
//
//  Created by Alban Diquet on 12/29/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <Foundation/Foundation.h>


@class FMDatabaseQueue;


@interface TSEncryptedDatabase : NSObject

@property (nonatomic, retain, readonly) FMDatabaseQueue *dbQueue; // Handle to use for accessing the database's content. It will be nil if the database hasn't been opened yet or if the storage master key is in a "locked" state
@property (nonatomic, retain, readonly) NSString *dbFilePath;


/**
 * Create a database encrypted with the storage master key and update the corresponding preference. 
 * @author Alban Diquet
 *
 * @param dbFilePath The file path where the database should be created.
 * @param preferenceName A BOOL preference that should be set to TRUE upon successful creation of the database.
 * @param error.
 * @return The newly created database or nil if an error occured.
 */
+(instancetype) databaseCreateAtFilePath:(NSString *)dbFilePath updateBoolPreference:(NSString *)preferenceName error:(NSError **)error;



/**
 * Open and decrypt a database using the storage master key. This will fail if the storage master key is in a "locked" state.
 * @author Alban Diquet
 *
 * @param dbFilePath The file path to the database.
 * @param the password for the encrypted database. Must not be nil, otherwise return will be nil
 * @param error.
 * @return The database or nil if an error occured.
 */
+(instancetype) databaseOpenAndDecryptAtFilePath:(NSString *)dbFilePath error:(NSError **)error;


/**
 * Erase an encrypted database and update the corresponding preference.
 * @author Alban Diquet
 *
 * @param dbFilePath The file path to the database.
 * @param preferenceName A BOOL preference that should be set to FALSE upon deletion of the database.
 */
+(void) databaseEraseAtFilePath:(NSString *)dbFilePath updateBoolPreference:(NSString *)preferenceName;


@end
