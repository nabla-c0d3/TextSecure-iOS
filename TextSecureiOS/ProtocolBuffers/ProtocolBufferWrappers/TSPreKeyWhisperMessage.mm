//
//  TSPrekeyWhisperMessage.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 1/6/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import "TSPrekeyWhisperMessage.hh"
#import "PreKeyWhisperMessage.pb.hh"
#import "TSEncryptedWhisperMessage.hh"
#import "TSECKeyPair.h"
#import "TSUserKeysDatabase.h"
#import "NSData+Base64.h"
@implementation TSPreKeyWhisperMessage

-(id)initWithPreKeyId:(NSNumber*)prekeyId  senderPrekey:(NSData*)prekey senderIdentityKey:(NSData*)identityKey message:(NSData*)messageContents {
    if(self=[super init]) {
        self.preKeyId = prekeyId;
        self.baseKey = prekey;
        self.identityKey = identityKey;
        self.message = messageContents;
    }
    return self;
}
-(id) initWithData:(NSData*) data {
    /*
     # ProtocolBuffer
     message PreKeyWhisperMessage {
     optional uint32 preKeyId    = 1;
     optional bytes  baseKey     = 2;
     optional bytes  identityKey = 3;
     optional bytes  message     = 4;
     }
     
     struct {
     opaque version[1];
     opaque PreKeyWhisperMessage[...];
     } TextSecure_PreKeyWhisperMessage;
     */
    if(self = [super init]) {
        // c++
        textsecure::PreKeyWhisperMessage *prekeyWhisperMessage = [self deserialize:data];
        uint32_t cppPreKeyId =  prekeyWhisperMessage->prekeyid();
        const std::string cppBaseKey = prekeyWhisperMessage->basekey();
        const std::string cppIdentityKey = prekeyWhisperMessage->identitykey();
        const std::string cppMessage = prekeyWhisperMessage->message();
        // c++->objective C
        self.preKeyId = [self cppUInt32ToNSNumber:cppPreKeyId];
        self.baseKey = [self cppStringToObjcData:cppBaseKey];
        self.identityKey = [self cppStringToObjcData:cppIdentityKey];
        self.message = [self cppStringToObjcData:cppMessage];
    }
    return self; // super is abstract class
}


-(const std::string) serializedProtocolBufferAsString {
    textsecure::PreKeyWhisperMessage *preKeyMessage = new textsecure::PreKeyWhisperMessage;
    // objective c->c++
    uint32_t cppPreKeyId =  [self objcNumberToCppUInt32:self.preKeyId];
    const std::string cppBaseKey = [self objcDataToCppString:self.baseKey];
    const std::string cppIdentityKey = [self objcDataToCppString:self.identityKey];
    const std::string cppMessage = [self objcDataToCppString:self.message];
    // c++->protocol buffer
    preKeyMessage->set_prekeyid(cppPreKeyId);
    preKeyMessage->set_basekey(cppBaseKey);
    preKeyMessage->set_identitykey(cppIdentityKey);
    preKeyMessage->set_message(cppMessage);
    std::string ps = preKeyMessage->SerializeAsString();
    return ps;
}

#pragma mark private methods
- (textsecure::PreKeyWhisperMessage *)deserialize:(NSData *)data {
    int len = [data length];
    char raw[len];
    textsecure::PreKeyWhisperMessage *messageSignal = new textsecure::PreKeyWhisperMessage;
    [data getBytes:raw length:len];
    messageSignal->ParseFromArray(raw, len);
    return messageSignal;
}




+(NSData*) constructFirstMessage:(NSData*)ciphertext theirPrekeyId:(NSNumber*) theirPrekeyId myCurrentEphemeral:(TSECKeyPair*) currentEphemeral myNextEphemeral:(TSECKeyPair*)myNextEphemeral{
    
    TSEncryptedWhisperMessage *encryptedWhisperMessage = [[TSEncryptedWhisperMessage alloc]
                                                          initWithEphemeralKey:[myNextEphemeral publicKey]
                                                          previousCounter:[NSNumber numberWithInt:0]
                                                          counter:[NSNumber numberWithInt:0]
                                                          encryptedMessage:ciphertext];
    // TODO: Error handling
    TSECKeyPair *identityKey = [TSUserKeysDatabase identityKeyWithError:nil];
    
    TSPreKeyWhisperMessage *prekeyMessage = [[TSPreKeyWhisperMessage alloc]
                                             initWithPreKeyId:theirPrekeyId
                                             senderPrekey:[currentEphemeral publicKey]
                                             senderIdentityKey:[identityKey publicKey]
                                             message:[encryptedWhisperMessage serializedProtocolBuffer]];
    
    return [prekeyMessage serializedProtocolBuffer];
}

@end
