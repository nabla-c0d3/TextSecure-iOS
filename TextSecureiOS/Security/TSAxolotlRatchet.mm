//
//  TSAxolotlRatchet.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 1/12/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import "TSAxolotlRatchet.hh"

#import "TSMessage.h"
#import "TSThread.h"
#import "TSContact.h"
#import "NSData+Base64.h"
#import "TSSubmitMessageRequest.h"
#import "TSMessagesManager.h"
#import "TSKeyManager.h"
#import "Cryptography.h"
#import "TSMessage.h"
#import "TSMessagesDatabase.h"
#import "TSUserKeysDatabase.h"
#import "TSThread.h"
#import "TSMessageSignal.hh"
#import "TSPushMessageContent.hh"
#import "TSWhisperMessage.hh"
#import "TSEncryptedWhisperMessage.hh"
#import "TSPreKeyWhisperMessage.hh"
#import "TSECKeyPair.h"
#import "TSRecipientPrekeyRequest.h"
#import "TSWhisperMessageKeys.h"
#import "TSHKDF.h"
#import "RKCK.h"
#import "TSContact.h"

@implementation TSAxolotlRatchet
-(id) initForThread:(TSThread*)threadForRatchet{
    if(self = [super init]) {
        self.thread = threadForRatchet;
    }
    return self;
}
#pragma mark public methods
+(void)sendMessage:(TSMessage*)message onThread:(TSThread*)thread ofType:(TSWhisperMessageType) messageType {
    [TSMessagesDatabase storeMessage:message fromThread:thread];
#warning always sending a prekey message for testing!
    messageType = TSPreKeyWhisperMessageType;
    TSAxolotlRatchet *ratchet = [[TSAxolotlRatchet alloc] initForThread:thread];
    switch (messageType) {
            
        case TSPreKeyWhisperMessageType:{
            // get a contact's prekey
            TSThread* thread = [TSThread threadWithContact:message.recipientId];
            [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSRecipientPrekeyRequest alloc] initWithRecipient:message.recipientId] success:^(AFHTTPRequestOperation *operation, id responseObject) {
                switch (operation.response.statusCode) {
                    case 200:{
                        
                        NSData* theirIdentityKey = [NSData dataFromBase64String:[responseObject objectForKey:@"identityKey"]];
                        NSData* theirEphemeralKey = [NSData dataFromBase64String:[responseObject objectForKey:@"publicKey"]];
                        NSNumber* theirPrekeyId = [responseObject objectForKey:@"keyId"];
                        TSECKeyPair *currentEphemeral = [ratchet ratchetSetupFirstSender:theirIdentityKey theirEphemeralKey:theirEphemeralKey];
                        NSData *encryptedMessage = [ratchet encryptTSMessage:message withKeys:[ratchet nextMessageKeysOnChain:TSSendingChain] withCTR:[NSNumber numberWithInt:0]];
                        TSECKeyPair *nextEphemeral = [TSMessagesDatabase getEphemeralOfSendingChain:thread]; // nil
                        NSData* encodedPreKeyWhisperMessage = [TSPreKeyWhisperMessage constructFirstMessage:encryptedMessage theirPrekeyId:theirPrekeyId myCurrentEphemeral:currentEphemeral myNextEphemeral:nextEphemeral];
                        [TSAxolotlRatchet receiveMessage:encodedPreKeyWhisperMessage];
                        [[TSMessagesManager sharedManager] submitMessageTo:message.recipientId message:[encodedPreKeyWhisperMessage base64EncodedString] ofType:TSPreKeyWhisperMessageType];
                        break;
                    }
                    default:
                        DLog(@"error sending message");
#warning Add error handling if not able to get contacts prekey
                        break;
                }
            } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
#warning right now it is not succesfully processing returned response, but is giving 200
                
            }];
            
            break;
        }
        case TSEncryptedWhisperMessageType: {
            // unsupported
            break;
        }
        case TSUnencryptedWhisperMessageType: {
            NSString *serializedMessage= [[TSPushMessageContent serializedPushMessageContent:message] base64EncodedStringWithOptions:0];
            [[TSMessagesManager sharedManager] submitMessageTo:message.recipientId message:serializedMessage ofType:messageType];
            break;
        }
        default:
            break;
    }
}

+(void)receiveMessage:(NSData*)data {
    NSData* decryptedPayload = [Cryptography decryptAppleMessagePayload:data withSignalingKey:[TSKeyManager getSignalingKeyToken]];
    TSMessageSignal *messageSignal = [[TSMessageSignal alloc] initWithData:decryptedPayload];
    TSAxolotlRatchet *ratchet = [[TSAxolotlRatchet alloc] initForThread:[TSThread threadWithContact:messageSignal.source]];
    
    TSMessage* message;
    
    switch (messageSignal.contentType) {
            
        case TSPreKeyWhisperMessageType: {
            TSPreKeyWhisperMessage* preKeyMessage = (TSPreKeyWhisperMessage*)messageSignal.message;
            TSEncryptedWhisperMessage* whisperMessage = (TSEncryptedWhisperMessage*)preKeyMessage.message;
            
            [ratchet ratchetSetupFirstReceiver:preKeyMessage.identityKey theirEphemeralKey:preKeyMessage.baseKey withMyPrekeyId:preKeyMessage.preKeyId];
            [ratchet updateChainsOnReceivedMessage:whisperMessage.ephemeralKey];
            
            
            TSWhisperMessageKeys* decryptionKeys =  [ratchet nextMessageKeysOnChain:TSReceivingChain];
            NSData* tsMessageDecryption = [Cryptography decryptCTRMode:whisperMessage.message withKeys:decryptionKeys withCounter:whisperMessage.counter];
            
            message = [TSMessage messageWithContent:[[NSString alloc] initWithData:tsMessageDecryption encoding:NSASCIIStringEncoding]
                                             sender:messageSignal.source
                                          recipient:[TSKeyManager getUsername]
                                               date:messageSignal.timestamp];
            break;
        }
            
        case TSEncryptedWhisperMessageType: {
            TSEncryptedWhisperMessage* whisperMessage = (TSEncryptedWhisperMessage*)messageSignal.message;
            [ratchet updateChainsOnReceivedMessage:whisperMessage.ephemeralKey];
            TSWhisperMessageKeys* decryptionKeys =  [ratchet nextMessageKeysOnChain:TSReceivingChain];
            NSData* tsMessageDecryption = [Cryptography decryptCTRMode:whisperMessage.message withKeys:decryptionKeys withCounter:whisperMessage.counter];
            
            message = [TSMessage messageWithContent:[[NSString alloc] initWithData:tsMessageDecryption encoding:NSASCIIStringEncoding]
                                             sender:messageSignal.source
                                          recipient:[TSKeyManager getUsername]
                                               date:messageSignal.timestamp];
            // TODO: Missing break; here ?
        }
            
        case TSUnencryptedWhisperMessageType: {
            TSPushMessageContent* messageContent = [[TSPushMessageContent alloc] initWithData:messageSignal.message.message];
            message = [messageSignal getTSMessage:messageContent];
            break;
        }
            
        default:
            // TODO: Missing error handling here ? Otherwise we're storing a nil message
            @throw [NSException exceptionWithName:@"Invalid state" reason:@"This should not happen" userInfo:nil];
            break;
    }

    [TSMessagesDatabase storeMessage:message fromThread:[TSThread threadWithContact: message.senderId]];
}


#pragma mark private methods
-(TSECKeyPair*) ratchetSetupFirstSender:(NSData*)theirIdentity theirEphemeralKey:(NSData*)theirEphemeral {
    /* after this we will have the CK of the Sending Chain */
    TSECKeyPair *ourIdentityKey = [TSUserKeysDatabase getIdentityKeyWithError:nil];
    TSECKeyPair *ourEphemeralKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
    NSData* ourMasterKey = [self masterKeyAlice:ourIdentityKey ourEphemeral:ourEphemeralKey   theirIdentityPublicKey:theirIdentity theirEphemeralPublicKey:theirEphemeral];
    RKCK* receivingChain = [self initialRootKey:ourMasterKey];
    
    TSECKeyPair* sendingKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
    RKCK* sendingChain = [receivingChain createChainWithNewEphemeral:sendingKey fromTheirProvideEphemeral:theirEphemeral]; // This will be used
    
    [receivingChain saveReceivingChainOnThread:self.thread withTheirEphemeral:theirEphemeral];
    [sendingChain saveSendingChainOnThread:self.thread withMyNewEphemeral:sendingKey];
    return ourEphemeralKey;
    
}

-(TSECKeyPair*)updateChainsOnReceivedMessage:(NSData*)theirNewEphemeral {
    RKCK *currentSendingChain = [RKCK currentSendingChain:self.thread];
    // generate new receiving chain from their new ephemeral ,my old epehemeral
    // decrypt the message we just got on this!
    RKCK *newReceivingChain = [currentSendingChain createChainWithNewEphemeral:currentSendingChain.ephemeral fromTheirProvideEphemeral:theirNewEphemeral];
    /// generate new sending chain with their new Ephemeral, my new epemeral
    // encyrpt messages with this and send it off
    TSECKeyPair* newSendingKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
    RKCK *newSendingChain = [newReceivingChain createChainWithNewEphemeral:newSendingKey fromTheirProvideEphemeral:theirNewEphemeral];
    [newReceivingChain saveReceivingChainOnThread:self.thread withTheirEphemeral:theirNewEphemeral];
    [newSendingChain saveSendingChainOnThread:self.thread withMyNewEphemeral:newSendingKey];
    return newSendingKey;
}


-(void) ratchetSetupFirstReceiver:(NSData*)theirIdentityKey theirEphemeralKey:(NSData*)theirEphemeralKey withMyPrekeyId:(NSNumber*)preKeyId  {
    /* after this we will have the CK of the Receiving Chain */
    TSECKeyPair *ourEphemeralKey = [TSUserKeysDatabase getPreKeyWithId:[preKeyId unsignedLongValue] error:nil];
    TSECKeyPair *ourIdentityKey =  [TSUserKeysDatabase getIdentityKeyWithError:nil];
    NSData* ourMasterKey = [self masterKeyBob:ourIdentityKey ourEphemeral:ourEphemeralKey theirIdentityPublicKey:theirIdentityKey theirEphemeralPublicKey:theirEphemeralKey];
    RKCK* sendingChain = [self initialRootKey:ourMasterKey];
    [sendingChain saveSendingChainOnThread:self.thread withMyNewEphemeral:ourEphemeralKey];
}


-(NSData*) encryptTSMessage:(TSMessage*)message  withKeys:(TSWhisperMessageKeys *)messageKeys withCTR:(NSNumber*)counter{
    return [Cryptography encryptCTRMode:[message.content dataUsingEncoding:NSASCIIStringEncoding] withKeys:messageKeys withCounter:counter];
}


#pragma mark helper methods

-(NSData*)masterKeyAlice:(TSECKeyPair*)ourIdentityKeyPair ourEphemeral:(TSECKeyPair*)ourEphemeralKeyPair theirIdentityPublicKey:(NSData*)theirIdentityPublicKey theirEphemeralPublicKey:(NSData*)theirEphemeralPublicKey {
    NSMutableData *masterKey = [NSMutableData data];
    [masterKey appendData:[ourIdentityKeyPair generateSharedSecretFromPublicKey:theirEphemeralPublicKey]];
    [masterKey appendData:[ourEphemeralKeyPair generateSharedSecretFromPublicKey:theirIdentityPublicKey]];
    [masterKey appendData:[ourEphemeralKeyPair generateSharedSecretFromPublicKey:theirEphemeralPublicKey]];
    return masterKey;
}

-(NSData*)masterKeyBob:(TSECKeyPair*)ourIdentityKeyPair ourEphemeral:(TSECKeyPair*)ourEphemeralKeyPair theirIdentityPublicKey:(NSData*)theirIdentityPublicKey theirEphemeralPublicKey:(NSData*)theirEphemeralPublicKey {
    NSMutableData *masterKey = [NSMutableData data];
    [masterKey appendData:[ourEphemeralKeyPair generateSharedSecretFromPublicKey:theirIdentityPublicKey]];
    [masterKey appendData:[ourIdentityKeyPair generateSharedSecretFromPublicKey:theirEphemeralPublicKey]];
    [masterKey appendData:[ourEphemeralKeyPair generateSharedSecretFromPublicKey:theirEphemeralPublicKey]];
    return masterKey;
}


-(TSWhisperMessageKeys*)nextMessageKeysOnChain:(TSChainType)chain {
    NSData* CK = [TSMessagesDatabase getCK:self.thread onChain:chain];
    /* Chain Key Derivation */
    int hmacKeyMK = 0x01;
    int hmacKeyCK = 0x02;
    NSData* nextMK = [Cryptography computeHMAC:CK withHMACKey:[NSData dataWithBytes:&hmacKeyMK length:sizeof(hmacKeyMK)]];
    NSData* nextCK = [Cryptography computeHMAC:CK  withHMACKey:[NSData dataWithBytes:&hmacKeyCK length:sizeof(hmacKeyCK)]];
    [TSMessagesDatabase setCK:nextCK onThread:self.thread onChain:chain];
    [TSMessagesDatabase getNPlusPlus:self.thread onChain:chain];
    return [self deriveTSWhisperMessageKeysFromMessageKey:nextMK];
}

-(RKCK*) initialRootKey:(NSData*)masterKey {
    return [RKCK withData:[TSHKDF deriveKeyFromMaterial:masterKey outputLength:64 info:[@"WhisperText" dataUsingEncoding:NSASCIIStringEncoding]]];
}


-(TSWhisperMessageKeys*) deriveTSWhisperMessageKeysFromMessageKey:(NSData*)nextMessageKey_MK {
    NSData* newCipherKeyAndMacKey  = [TSHKDF deriveKeyFromMaterial:nextMessageKey_MK outputLength:64 info:[@"WhisperMessageKeys" dataUsingEncoding:NSASCIIStringEncoding]];
    NSData* cipherKey = [newCipherKeyAndMacKey subdataWithRange:NSMakeRange(0, 32)];
    NSData* macKey = [newCipherKeyAndMacKey subdataWithRange:NSMakeRange(32, 32)];
    // we want to return something here  or use this locally
    return [[TSWhisperMessageKeys alloc] initWithCipherKey:cipherKey macKey:macKey];
}




@end
