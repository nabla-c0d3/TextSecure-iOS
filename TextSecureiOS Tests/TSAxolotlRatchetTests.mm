//
//  TSAxolotlProtocolTests.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 1/12/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TSAxolotlRatchet.hh"
#import "Cryptography.h"
#import "TSECKeyPair.h"
#import "TSHKDF.h"
#import "TSWhisperMessageKeys.h"
#import "TSMessagesDatabase.h"
#import "TSStorageError.h"
#import "Cryptography.h"
#import "TSStorageMasterKey.h"
#import "TSThread.h"
#import "TSContact.h"
#import "TSECKeyPair.h"
#import "TSMessage.h"
#import "TSStorageMasterKey.h"
#import "TSUserKeysDatabase.h"
#import "RKCK.h"
#import "TSKeyManager.h"
static NSString *masterPw = @"1234test";
@interface TSAxolotlRatchetTests : XCTestCase
@property (nonatomic,strong) TSAxolotlRatchet *alice;
@property (nonatomic,strong) NSString* aliceUserName;
@property (nonatomic,strong) NSString* bobUserName;

@property (nonatomic,strong) TSAxolotlRatchet *bob;
@property (nonatomic,strong) TSThread* thread1;
@property (nonatomic,strong) TSMessage* message1;
@property (nonatomic,strong) TSThread* thread2;
@property (nonatomic,strong) TSMessage* message2;


@end


// To avoid + h files
@interface TSAxolotlRatchet (Test)


#pragma mark private methods
-(TSECKeyPair*) ratchetSetupFirstSender:(NSData*)theirIdentity theirEphemeralKey:(NSData*)theirEphemeral;
-(void) ratchetSetupFirstReceiver:(NSData*)theirIdentityKey theirEphemeralKey:(NSData*)theirEphemeralKey withMyPrekeyId:(NSNumber*)preKeyId;
-(TSECKeyPair*)updateChainsOnReceivedMessage:(NSData*)theirNewEphemeral;
-(TSWhisperMessageKeys*)nextMessageKeysOnChain:(TSChainType)chain;
-(RKCK*) initialRootKey:(NSData*)masterKey;
-(TSWhisperMessageKeys*) deriveTSWhisperMessageKeysFromMessageKey:(NSData*)nextMessageKey_MK;


#pragma mark private helper methods
-(NSData*)masterKeyAlice:(TSECKeyPair*)ourIdentityKeyPair ourEphemeral:(TSECKeyPair*)ourEphemeralKeyPair theirIdentityPublicKey:(NSData*)theirIdentityPublicKey theirEphemeralPublicKey:(NSData*)theirEphemeralPublicKey;
-(NSData*)masterKeyBob:(TSECKeyPair*)ourIdentityKeyPair ourEphemeral:(TSECKeyPair*)ourEphemeralKeyPair theirIdentityPublicKey:(NSData*)theirIdentityPublicKey theirEphemeralPublicKey:(NSData*)theirEphemeralPublicKey;
-(NSData*) encryptTSMessage:(TSMessage*)message  withKeys:(TSWhisperMessageKeys *)messageKeys withCTR:(NSNumber*)counter;


#pragma mark private test methods
/* TCO = testing case/class only */
+(MKCK*)nextMessageAndChainKeyTCO:(NSData*)CK;
+(RKCK*)newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:(NSData*)theirPublicEphemeral fromMyNewEphemeral:(TSECKeyPair*)newEphemeral withExistingRK:(NSData*)existingRK;

@end


@implementation TSAxolotlRatchet (Test)

+(MKCK*)nextMessageAndChainKeyFromChainKeyTCO:(NSData*)CK {
  /* Chain Key Derivation */
  int hmacKeyMK = 0x01;
  int hmacKeyCK = 0x02;
  NSData* nextMK = [Cryptography computeHMAC:CK withHMACKey:[NSData dataWithBytes:&hmacKeyMK length:sizeof(hmacKeyMK)]];

  NSData* nextCK = [Cryptography computeHMAC:CK  withHMACKey:[NSData dataWithBytes:&hmacKeyCK length:sizeof(hmacKeyCK)]];
  MKCK *mkCK = [[MKCK alloc] init];
  mkCK.MK = nextMK;
  mkCK.CK = nextMK;
  return mkCK;
}

+(RKCK*)newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:(NSData*)theirPublicEphemeral fromMyNewEphemeral:(TSECKeyPair*)newEphemeral withExistingRK:(NSData *)existingRK {
  NSData* inputKeyMaterial = [newEphemeral generateSharedSecretFromPublicKey:theirPublicEphemeral];
  return [RKCK withData:[TSHKDF deriveKeyFromMaterial:inputKeyMaterial outputLength:64 info:[@"WhisperRatchet" dataUsingEncoding:NSASCIIStringEncoding] salt:existingRK]];
  
}


@end


@implementation TSAxolotlRatchetTests

- (void)setUp
{

  [super setUp];
  self.aliceUserName = @"12345";
  self.bobUserName = @"678910";

  self.thread1 = [TSThread threadWithContacts:@[[[TSContact alloc] initWithRegisteredID:self.aliceUserName],
                                                                            [[TSContact alloc] initWithRegisteredID:self.bobUserName]]];
  
  
  self.message1 = [TSMessage messageWithContent:@"hey" sender:self.aliceUserName recipient:self.bobUserName date:[NSDate date]];
  self.alice = [[TSAxolotlRatchet alloc] initForThread:self.thread1];


  self.thread2 = [TSThread threadWithContacts:@[[[TSContact alloc] initWithRegisteredID:self.aliceUserName],
                                                                           [[TSContact alloc] initWithRegisteredID:self.bobUserName]]];

  self.message2 = [TSMessage messageWithContent:@"yo" sender:self.bobUserName recipient:self.aliceUserName date:[NSDate date]];
  self.bob = [[TSAxolotlRatchet alloc] initForThread:self.thread2];

  // Remove any existing DB
  [TSMessagesDatabase databaseErase];
  
  
  [TSStorageMasterKey eraseStorageMasterKey];
  [TSStorageMasterKey createStorageMasterKeyWithPassword:masterPw error:nil];
  
  NSError *error;
    
  // tests data base creation
    
  XCTAssertTrue([TSMessagesDatabase databaseCreateWithError:&error], @"message db creation failed");
  XCTAssertNil(error, @"message db creation returned an error");
    
  
   // user keys database is bob's
  // Remove any existing DB
  [TSUserKeysDatabase databaseErase];
  XCTAssertTrue([TSUserKeysDatabase databaseCreateUserKeysWithError:&error], @"message db creation failed");

  
  
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [super tearDown];
}

-(void) testMasterKeyGeneration {
  TSECKeyPair *aliceIdentityKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  TSECKeyPair *aliceEphemeralKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  TSECKeyPair *bobIdentityKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  TSECKeyPair *bobEphemeralKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  NSData* aliceMasterKey = [self.alice masterKeyAlice:aliceIdentityKey ourEphemeral:aliceEphemeralKey   theirIdentityPublicKey:[bobIdentityKey getPublicKey] theirEphemeralPublicKey:[bobEphemeralKey getPublicKey]];
  
  
  NSData* bobMasterKey = [self.bob masterKeyBob:bobIdentityKey ourEphemeral:bobEphemeralKey theirIdentityPublicKey:[aliceIdentityKey getPublicKey] theirEphemeralPublicKey:[aliceEphemeralKey getPublicKey]];
  XCTAssertTrue([aliceMasterKey isEqualToData:bobMasterKey], @"alice and bob master keys not equal");
}

-(void) testDemoRatchet {
  // more of a demonstration of the protocol than a test of the implementation
  TSECKeyPair *aliceIdentityKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  TSECKeyPair *aliceEphemeralKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  TSECKeyPair *bobIdentityKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  TSECKeyPair *bobEphemeralKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  // ratchet alice
  NSData* aliceMasterKey = [self.alice masterKeyAlice:aliceIdentityKey ourEphemeral:aliceEphemeralKey   theirIdentityPublicKey:[bobIdentityKey getPublicKey] theirEphemeralPublicKey:[bobEphemeralKey getPublicKey]]; // ECDH(A0,B0)
  
  
  RKCK* aliceSending0= [RKCK withData:[TSHKDF deriveKeyFromMaterial:aliceMasterKey outputLength:64 info:[@"WhisperText" dataUsingEncoding:NSASCIIStringEncoding] salt:[NSData data]]]; // Initial RK
  
  
  // Now alice will create a sending a few more messages along side the next ratchet key A1. We can already do this as we have Bob's B1
  // She generates a future ratchet chain
  TSECKeyPair *A1 = [TSECKeyPair keyPairGenerateWithPreKeyId:0]; // generate A1 for ratchet on sending chain
  RKCK* aliceSendingChain0 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[bobEphemeralKey getPublicKey] fromMyNewEphemeral:A1 withExistingRK:aliceSending0.RK]; // ECDH(A1,B0)
  
  MKCK* aliceSendingChain0Message0 = [TSAxolotlRatchet nextMessageAndChainKeyFromChainKeyTCO:aliceSendingChain0.CK]; //CK-A1-B0 MK0
  // She sends messages on the current chain, along with A1 to be used on her next receiving chain
  MKCK* aliceSendingChain0Message1 = [TSAxolotlRatchet nextMessageAndChainKeyFromChainKeyTCO:aliceSendingChain0Message0.CK]; //CK-A1-B0 MK1
  MKCK* aliceSendingChain0Message2 =[TSAxolotlRatchet nextMessageAndChainKeyFromChainKeyTCO:aliceSendingChain0Message1.CK]; //CK-A1-B0 MK2

  // Bob gets these messages, and is ready to decrypt
  NSData* bobMasterKey = [self.alice masterKeyBob:bobIdentityKey ourEphemeral:bobEphemeralKey theirIdentityPublicKey:[aliceIdentityKey getPublicKey] theirEphemeralPublicKey:[aliceEphemeralKey getPublicKey]]; // ECDH(A0,B0)
  XCTAssertTrue([aliceMasterKey isEqualToData:bobMasterKey], @"alice and bob master keys not equal");

  
  RKCK* bobReceiving0= [RKCK withData:[TSHKDF deriveKeyFromMaterial:bobMasterKey outputLength:64 info:[@"WhisperText" dataUsingEncoding:NSASCIIStringEncoding] salt:[NSData data]]]; // inital RK
  XCTAssertTrue([aliceSending0.RK isEqualToData:bobReceiving0.RK], @"alice and bob initial RK and CK not equal");
  XCTAssertTrue([aliceSending0.CK isEqualToData:bobReceiving0.CK], @"alice and bob initial RK and CK not equal");

  // he has A1 public so he's able to then generate the sending chain of Alice's (his receiving chain)
  RKCK* bobReceivingChain0 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[A1 getPublicKey] fromMyNewEphemeral:bobEphemeralKey withExistingRK:bobReceiving0.RK]; // ECDH(A1,B0)
  XCTAssertTrue([aliceSendingChain0.RK isEqualToData:bobReceivingChain0.RK], @"alice and bob first ratchet RK CK not equal");
  XCTAssertTrue([aliceSendingChain0.CK isEqualToData:bobReceivingChain0.CK], @"alice and bob first ratchet RK CK not equal");
  // Bob's next sending chain will use A1 and his own B1 to generate a message
  TSECKeyPair *B1 = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  RKCK* bobSending0 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[A1 getPublicKey] fromMyNewEphemeral:B1 withExistingRK:bobReceivingChain0.RK];


  
  // CK-A1-B0
  MKCK* bobReceivingChain0Message0 = [TSAxolotlRatchet nextMessageAndChainKeyFromChainKeyTCO:bobReceivingChain0.CK]; //CK-A1-B0 MK0
  MKCK* bobReceivingChain0Message1 = [TSAxolotlRatchet nextMessageAndChainKeyFromChainKeyTCO:bobReceivingChain0Message0.CK]; //CK-A1-B0 MK1
  MKCK* bobReceivingChain0Message2 = [TSAxolotlRatchet nextMessageAndChainKeyFromChainKeyTCO: bobReceivingChain0Message1.CK]; //CK-A1-B0 MK2


  XCTAssertTrue([aliceSendingChain0Message0.MK isEqualToData:bobReceivingChain0Message0.MK], @"alice and bob first message on chain MK CK not equal");
  XCTAssertTrue([aliceSendingChain0Message0.CK isEqualToData:bobReceivingChain0Message0.CK], @"alice and bob first message on chain MK CK not equal");

  XCTAssertTrue([aliceSendingChain0Message1.MK isEqualToData:bobReceivingChain0Message1.MK], @"alice and bob second message on chain MK CK not equal");
  XCTAssertTrue([aliceSendingChain0Message1.CK isEqualToData:bobReceivingChain0Message1.CK], @"alice and bob second message on chain MK CK not equal");

  XCTAssertTrue([aliceSendingChain0Message2.MK isEqualToData:bobReceivingChain0Message2.MK], @"alice and bob third message on chain MK CK not equal");
  XCTAssertTrue([aliceSendingChain0Message2.CK isEqualToData:bobReceivingChain0Message2.CK], @"alice and bob third message on chain MK CK not equal");

  // Testing the cipher and mac key generation
  TSWhisperMessageKeys* aliceSendingKeysMK0 = [self.alice  deriveTSWhisperMessageKeysFromMessageKey:aliceSendingChain0Message0.MK];
  TSWhisperMessageKeys* bobReceivingKeysMK0 = [self.alice  deriveTSWhisperMessageKeysFromMessageKey:bobReceivingChain0Message0.MK];
  XCTAssertTrue([aliceSendingKeysMK0.cipherKey isEqualToData:bobReceivingKeysMK0.cipherKey], @"cipher keys alice and bob for MK0 not equal");
  XCTAssertTrue([aliceSendingKeysMK0.macKey isEqualToData:bobReceivingKeysMK0.macKey], @"mac keys alice and bob for MK0 not equal");
  XCTAssertTrue([aliceSendingKeysMK0.cipherKey length]==32, @"cipher key wrong size");
  XCTAssertTrue([aliceSendingKeysMK0.macKey length]==32, @"mac key wrong size");
  
  
  // Alice, on receiving B1 and the message encrypted with it updates her receiving chain with A1,B1 (decrypted the received message on that chain) and her sending chain with a new public ephemeral of hers A2
  RKCK* aliceReceiving0 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[B1 getPublicKey] fromMyNewEphemeral:A1 withExistingRK:aliceSendingChain0.RK];
  XCTAssertTrue([aliceReceiving0.RK isEqualToData:bobSending0.RK], @"alice and bobs chains are out of sync");
  XCTAssertTrue([aliceReceiving0.CK isEqualToData:bobSending0.CK], @"alice and bobs chains are out of sync");
  
  // She also updates her sending chain with a new public ephemeral of hers A2

  TSECKeyPair *A2 = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  RKCK* aliceSending1 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[B1 getPublicKey] fromMyNewEphemeral:A2 withExistingRK:aliceReceiving0.RK];
  // She can send this to Bob with a message encrypted on it, and he will be able to decrypt
  
  
  // Bob on receipt of A2 and a message encrypted with A2 can update his receiving chain and generate a new sending chain
  
  RKCK* bobReceiving1 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[A2 getPublicKey] fromMyNewEphemeral:B1 withExistingRK:bobSending0.RK];
  XCTAssertTrue([bobReceiving1.RK isEqualToData:aliceSending1.RK], @"alice and bobs chains are out of sync");
  XCTAssertTrue([bobReceiving1.CK isEqualToData:aliceSending1.CK], @"alice and bobs chains are out of sync");
  
  // He also updates his sending chain with a new public ephemeral of his B2
  
  TSECKeyPair *B2 = [TSECKeyPair keyPairGenerateWithPreKeyId:0];
  RKCK* bobSending1 = [TSAxolotlRatchet newRootKeyAndChainKeyWithTheirPublicEphemeralTCO:[A2 getPublicKey] fromMyNewEphemeral:B2 withExistingRK:bobReceiving1.RK];
  
  // and so on....

}

-(void) testFirstMessageExchange {
  // note in this test alice's identity key = bob's as they are sharing the same keydb. their ephemeral keys will be different.
  TSECKeyPair* aliceIdentityKey = [TSUserKeysDatabase getIdentityKeyWithError:nil];
  TSECKeyPair* aliceInitialEphemeralKey = [TSECKeyPair keyPairGenerateWithPreKeyId:0];

  
  XCTAssertTrue([[TSUserKeysDatabase getAllPreKeysWithError:nil] count]>0, @"no prekeys in database");
  TSECKeyPair* bobEphemeralKey =  [[TSUserKeysDatabase getAllPreKeysWithError:nil] objectAtIndex:0];
  TSECKeyPair* bobIdentityKey = [TSUserKeysDatabase getIdentityKeyWithError:nil];
  
  XCTAssertNotNil(bobEphemeralKey, @"bob ephemeral key nil");
  XCTAssertNotNil(bobIdentityKey, @"bob identity key nil");
  uint32_t prekeyId = [bobEphemeralKey getPreKeyId];
  // Alice goes first
  [TSKeyManager storeUsername:self.aliceUserName];
  [self.alice ratchetSetupFirstSender:[bobIdentityKey getPublicKey] theirEphemeralKey:[bobEphemeralKey getPublicKey]];
 
  TSECKeyPair* aliceSendingKey = [TSMessagesDatabase getEphemeralOfSendingChain:self.thread1];
  XCTAssertNotNil(aliceSendingKey, @"alice sending key is nil");
  NSData *encryptedMessage = [self.alice encryptTSMessage:self.message1 withKeys:[self.alice nextMessageKeysOnChain:TSSendingChain] withCTR:[NSNumber numberWithInt:0]];
  

  // Clobbers any keys of alices
  [TSKeyManager storeUsername:self.bobUserName];
  [self.bob ratchetSetupFirstReceiver:[aliceIdentityKey getPublicKey] theirEphemeralKey:[aliceInitialEphemeralKey getPublicKey] withMyPrekeyId:[NSNumber numberWithInt:prekeyId]];
  
  [self.bob updateChainsOnReceivedMessage:[aliceSendingKey getPublicKey]];
  
  
  TSWhisperMessageKeys* decryptionKeys =  [self.bob nextMessageKeysOnChain:TSReceivingChain];
  NSData* tsMessageDecryption = [Cryptography decryptCTRMode:encryptedMessage withKeys:decryptionKeys withCounter:[NSNumber numberWithInt:0]];
  
  TSMessage* decryptedMessage=[TSMessage messageWithContent:[[NSString alloc] initWithData:tsMessageDecryption encoding:NSASCIIStringEncoding] sender:self.aliceUserName recipient:self.bobUserName date:[NSDate date]];
  
  XCTAssertTrue([decryptedMessage.content isEqualToString:self.message1.content], @"message encrypted by alice not equal to that decrypted by bob");
}
@end
