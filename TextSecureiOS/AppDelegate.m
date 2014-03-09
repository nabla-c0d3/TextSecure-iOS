//
//  AppDelegate.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/24/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "AppDelegate.h"
#import "Cryptography.h"
#import "TSKeyManager.h"
#import <PonyDebugger/PonyDebugger.h> //ponyd serve --listen-interface=127.0.0.1
#import "TSMessagesDatabase.h"
#import "TSStorageMasterKey.h"
#import "TSStorageError.h"
#import "TSRegisterForPushRequest.h"
#import "NSString+Conversion.h"
#import "TSMessagesManager.h"
#import "NSData+Base64.h"
#import "TSAttachmentManager.h"
#import "TSMessage.h"
#import "TSAttachment.h"
#import "TSWaitingPushMessageDatabase.h"
#import "TSStorageMasterKey.h"
@implementation AppDelegate

#pragma mark - UIApplication delegate methods

#define firstLaunchKey @"FirstLaunch"

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
#warning remove
    // UIAppearance proxy setup
    [[UIBarButtonItem appearance] setTitleTextAttributes:@{NSForegroundColorAttributeName : [UIColor colorWithRed:33/255. green:127/255. blue:248/255. alpha:1]} forState:UIControlStateNormal];
    [[UIBarButtonItem appearance] setTitleTextAttributes:@{NSForegroundColorAttributeName: [UIColor grayColor]} forState:UIControlStateDisabled];
    
    
    // If this is the first launch, we want to remove stuff from the Keychain that might be there from a previous install
    
    if (![[NSUserDefaults standardUserDefaults] boolForKey:firstLaunchKey]) {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:firstLaunchKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [TSKeyManager removeAllKeychainItems];
        DLog(@"First Launch");
    }
    
    [self setDefaultUserSettings];
    [self updateBasedOnUserSettings];
    
#ifdef DEBUG
	[[BITHockeyManager sharedHockeyManager] configureWithBetaIdentifier:@"9e6b7f4732558ba8480fb2bcd0a5c3da"
														 liveIdentifier:@"9e6b7f4732558ba8480fb2bcd0a5c3da"
															   delegate:self];
	[[BITHockeyManager sharedHockeyManager] startManager];
    
    PDDebugger *debugger = [PDDebugger defaultInstance];
    [debugger connectToURL:[NSURL URLWithString:@"ws://localhost:9000/device"]];
    [debugger enableNetworkTrafficDebugging];
    [debugger forwardAllNetworkTraffic];
#endif
	
	if(launchOptions!=nil) {
		[self handlePush:launchOptions];
	}
	if([TSKeyManager hasVerifiedPhoneNumber] && [TSMessagesDatabase databaseWasCreated]) {
		[[UIApplication sharedApplication] registerForRemoteNotificationTypes:
		 (UIRemoteNotificationTypeBadge | UIRemoteNotificationTypeSound | UIRemoteNotificationTypeAlert)];
	}

    // we need to create the window here, if we do it in -applicationDidEnterBackground it's too late and it
    // doesn't get screenshotted.
    self.blankWindow = ({
        UIWindow *window = [[UIWindow alloc] initWithFrame:self.window.bounds];
        window.hidden = YES;
        window.userInteractionEnabled = NO;
        window.windowLevel = CGFLOAT_MAX;
        window;
    });
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(handlePushesQueuedInDB) name:TSStorageMasterKeyWasUnlockedNotification object:nil];
	return YES;
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // obscure the application's windows
    self.blankWindow.rootViewController = [[UIViewController alloc] init];
    UIImageView *imageView = [[UIImageView alloc] initWithFrame:self.blankWindow.bounds];
    if (self.blankWindow.bounds.size.height == 568) {
        imageView.image = [UIImage imageNamed:@"Default-568h"];
    } else {
        imageView.image = [UIImage imageNamed:@"Default"];
    }
    imageView.opaque = YES;
    [self.blankWindow.rootViewController.view addSubview:imageView];
    self.blankWindow.hidden = NO;
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    self.blankWindow.rootViewController = nil;
    self.blankWindow.hidden = YES;
    [self updateBasedOnUserSettings];
}



#pragma mark settings
-(void) setDefaultUserSettings {
    /* this is as apparently defaults set in settings bundle are just display defaults, must still set in code */
    NSDictionary *appDefaults = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithBool:NO] ,@"resetDB",[NSNumber numberWithBool:NO],kStorageMasterKeyWasCreated, nil];
    [[NSUserDefaults standardUserDefaults] registerDefaults:appDefaults];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (void)updateBasedOnUserSettings {
    if([[NSUserDefaults standardUserDefaults] boolForKey:@"resetDB"]) {
        [TSKeyManager removeAllKeychainItems];
        [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:[[NSBundle mainBundle] bundleIdentifier]];
        [[NSUserDefaults standardUserDefaults] synchronize];
        exit(0);
    }
}



#pragma mark - Push notifications

- (void)application:(UIApplication*)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData*)deviceToken {
	NSString *stringToken = [[deviceToken description] stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
	stringToken = [stringToken stringByReplacingOccurrencesOfString:@" " withString:@""];
	
    [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSRegisterForPushRequest alloc] initWithPushIdentifier:stringToken] success:^(AFHTTPRequestOperation *operation, id responseObject) {
        
        switch (operation.response.statusCode) {
            case 200:
                DLog(@"Device registered for push notifications");
                break;
                
            default:
#warning Add error handling if not able to send the token
                break;
        }
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
#warning Add error handling if not able to send the token
    }];
    
}

- (void)application:(UIApplication*)application didFailToRegisterForRemoteNotificationsWithError:(NSError*)error {
    
    
    //    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"TextSecure needs push notifications" message:@"We couldn't enable push notifications. TexSecure uses them heavily. Please try registering again." delegate:self cancelButtonTitle:@"Ok" otherButtonTitles:nil, nil];
    //    [alert show];
    
#ifdef DEBUG
#warning registering with dummy ID so that we can proceed in the simulator. You'll want to change this!
    NSData *deviceToken = [NSData dataFromBase64String:[@"christine" base64Encoded]];
    [self application:application didRegisterForRemoteNotificationsWithDeviceToken:deviceToken];
#endif
    
}


- (void)application:(UIApplication *)application didReceiveRemoteNotification:(NSDictionary *)userInfo {
	[self handlePush:userInfo];
}

-(void) handlePush:(NSDictionary *)pushInfo {
    if(![TSStorageMasterKey isStorageMasterKeyLocked]) {
        [[TSMessagesManager sharedManager]receiveMessagePush:pushInfo];
    }
    else {
        // Store in queue
        [TSWaitingPushMessageDatabase queuePush:pushInfo];
    }
}

-(void) handlePushesQueuedInDB {
    // This method is triggered whenever DB is unlocked
    if(![TSStorageMasterKey isStorageMasterKeyLocked]) {
        for(NSDictionary* pushInfo in [TSWaitingPushMessageDatabase getPushesInReceiptOrder]) {
            [[TSMessagesManager sharedManager] receiveMessagePush:pushInfo];
        }
    }
    [TSWaitingPushMessageDatabase finishPushesQueued];
}

#pragma mark - HockeyApp Delegate Methods

#ifdef DEBUG
- (NSString *)customDeviceIdentifierForUpdateManager:(BITUpdateManager *)updateManager {
#ifndef CONFIGURATION_AppStore
	if ([[UIDevice currentDevice] respondsToSelector:@selector(uniqueIdentifier)])
		return [[UIDevice currentDevice] performSelector:@selector(uniqueIdentifier)];
#endif
	return nil;
}
#endif

@end
