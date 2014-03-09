//
//  TSUserKeysDatabaseTests.m
//  TextSecureiOS
//
//  Created by Alban Diquet on 12/29/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TSUserKeysDatabase.h"
#import "TSStorageMasterKey.h"

@interface TSUserKeysDatabaseTests : XCTestCase

@end


static NSString *storageKeyPw = @"1234test";


@implementation TSUserKeysDatabaseTests

- (void)setUp
{
    [super setUp];
    
    // Remove any existing DB
    [TSUserKeysDatabase databaseErase];
    
    // Create a storage master key
    [TSStorageMasterKey eraseStorageMasterKey];
    [TSStorageMasterKey createStorageMasterKeyWithPassword:storageKeyPw error:nil];
}

- (void)tearDown
{
    // Put teardown code here; it will be run once, after the last test case.
    [super tearDown];
}


- (void)testDatabaseCreate
{
    NSError *error = nil;
    XCTAssertTrue([TSUserKeysDatabase databaseCreateUserKeysWithError:&error], @"database creation failed");
    XCTAssertNil(error, @"database creation returned an error");
    
    
    XCTAssertNotNil([TSUserKeysDatabase allPreKeysWithError:nil], @"database creation returned nil prekeys");
    XCTAssertNotNil([TSUserKeysDatabase identityKeyWithError:nil], @"database creation returned nil identity key");
    // Check for key of last resort
    XCTAssertNotNil([TSUserKeysDatabase preKeyWithId:0xFFFFFF error:nil], @"database creation returned nil for key of last resort");
}





@end
