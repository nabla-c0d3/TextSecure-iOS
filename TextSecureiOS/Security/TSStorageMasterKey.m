//
//  TSStorageMasterKey.m
//  TextSecureiOS
//
//  Created by Alban Diquet on 12/29/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "TSStorageMasterKey.h"
#import "Cryptography.h"
#import "RNEncryptor.h"
#import "RNDecryptor.h"
#import "KeychainWrapper.h"
#import "NSData+Base64.h"
#import "TSStorageError.h"

NSString *const TSStorageMasterKeyWasUnlockedNotification = @"com.whispersystems.storagemasterkey.unlocked";
NSString *const TSStorageMasterKeyWasLockedNotification = @"com.whispersystems.storagemasterkey.locked";


static uint8_t storageMasterKey[MASTER_KEY_SIZE] = {0};
static BOOL isMasterKeyLocked = TRUE;


@implementation TSStorageMasterKey


+(NSData*) createStorageMasterKeyWithPassword:(NSString *)userPassword error:(NSError **) error {
    
    if ([TSStorageMasterKey wasStorageMasterKeyCreated]) {
        // A master key has already been generated on this device
        if (error){
            *error = [TSStorageError errorStorageKeyAlreadyCreated];
        }
        return nil;
    }
    
    NSData *masterKey = [Cryptography generateRandomBytes:36];
    if(!masterKey) {
        if (error) {
            *error = [TSStorageError errorStorageKeyCreationFailed];
        }
        return nil;
    }
    
    NSData *encryptedMasterKey = [RNEncryptor encryptData:masterKey withSettings:kRNCryptorAES256Settings password:userPassword error:nil];
    if(!encryptedMasterKey) {
        if (error) {
            *error = [TSStorageError errorStorageKeyCreationFailed];
        }
        return nil;
    }
    
    // Store the encrypted master key in the Keychain
    if (![KeychainWrapper createKeychainValue:[encryptedMasterKey base64EncodedString] forIdentifier:encryptedMasterSecretKeyStorageId]) {
        if (error) {
            *error = [TSStorageError errorStorageKeyCreationFailed];
        }
        return nil;
    }
    
    // Store the decrypted master key in the local buffer
    isMasterKeyLocked = FALSE;
    memcpy(storageMasterKey, [masterKey bytes], MASTER_KEY_SIZE);
    
    // Update user preferences
    [[NSUserDefaults standardUserDefaults] setBool:TRUE forKey:kStorageMasterKeyWasCreated];
    [[NSUserDefaults standardUserDefaults] synchronize];
    return [NSData dataWithBytesNoCopy:storageMasterKey length:MASTER_KEY_SIZE freeWhenDone:NO];
}


+(BOOL) wasStorageMasterKeyCreated {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kStorageMasterKeyWasCreated];
}


+(NSData*) unlockStorageMasterKeyUsingPassword:(NSString *)userPassword error:(NSError **)error {
    
    if (![TSStorageMasterKey wasStorageMasterKeyCreated]) {
        // A master key has not been generated on this device yet
        if (error){
            *error = [TSStorageError errorStorageKeyNotCreated];
        }
        return nil;
    }
    
    NSString *encryptedStorageMasterKey = [KeychainWrapper keychainStringFromMatchingIdentifier:encryptedMasterSecretKeyStorageId];
    if (!encryptedStorageMasterKey) {
        if (error) {
            *error = [TSStorageError errorStorageKeyCorrupted];
        }
        return nil;
    }
    
    NSData *masterKey = [RNDecryptor decryptData:[NSData dataFromBase64String:encryptedStorageMasterKey] withPassword:userPassword error:error];
    if (!masterKey)  {
        if (error && ([*error domain] == kRNCryptorErrorDomain) && ([*error code] == kRNCryptorHMACMismatch)) {
            *error = [TSStorageError errorInvalidPassword];
        }
        else if (error) {
            *error = [TSStorageError errorStorageKeyCorrupted];
        }
        return nil;
    }
    
    isMasterKeyLocked = FALSE;
    memcpy(storageMasterKey, [masterKey bytes], MASTER_KEY_SIZE);
    [[NSNotificationCenter defaultCenter] postNotificationName:TSStorageMasterKeyWasUnlockedNotification object:self];
    
    return [NSData dataWithBytesNoCopy:storageMasterKey length:MASTER_KEY_SIZE freeWhenDone:NO];
}


+(NSData*) getStorageMasterKeyWithError:(NSError **)error {

    if (![TSStorageMasterKey wasStorageMasterKeyCreated]) {
        if (error) {
            *error = [TSStorageError errorStorageKeyNotCreated];
        }
        return nil;
    }
    
    if (isMasterKeyLocked) {
        if (error) {
            *error = [TSStorageError errorStorageKeyLocked];
        }
        return nil;
    }
    
    return [NSData dataWithBytesNoCopy:storageMasterKey length:MASTER_KEY_SIZE freeWhenDone:NO];
}


+(void) lockStorageMasterKey {
    isMasterKeyLocked = TRUE;
    
    // Best-effort "secure" erase; may be overkill and may not work at all
    memset(storageMasterKey, 0, MASTER_KEY_SIZE);
    
    [[NSNotificationCenter defaultCenter] postNotificationName:TSStorageMasterKeyWasLockedNotification object:nil];
}


+(BOOL) isStorageMasterKeyLocked {
    return isMasterKeyLocked;
}


+(void) eraseStorageMasterKey {
    [[NSNotificationCenter defaultCenter] postNotificationName:TSStorageMasterKeyWasLockedNotification object:nil];
    [[NSUserDefaults standardUserDefaults] setBool:FALSE forKey:kStorageMasterKeyWasCreated];
    [[NSUserDefaults standardUserDefaults] synchronize];
    isMasterKeyLocked = TRUE;
    memset(storageMasterKey, 0, MASTER_KEY_SIZE);
    [KeychainWrapper deleteItemFromKeychainWithIdentifier:encryptedMasterSecretKeyStorageId];
}
    
    
@end
