//
//  TSNetworkManager.m
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 9/27/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//


#import "TSNetworkManager.h"
#import "TSRequest.h"
#import "TSKeyManager.h"
#import "TSServerCodeVerificationRequest.h"
#import "TSUploadAttachment.h"
#import "TSAttachment.h"
#import <AFNetworking/AFURLRequestSerialization.h>

@implementation TSNetworkManager

#pragma mark Singleton implementation

+ (id)sharedManager {
    static TSNetworkManager *sharedMyManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedMyManager = [[self alloc] init];
    });
    return sharedMyManager;
}

- (id)init {
    if (self = [super init]) {
        operationManager = [[AFHTTPRequestOperationManager manager] initWithBaseURL:[[NSURL alloc] initWithString:textSecureServer]];
        operationManager.securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
        operationManager.requestSerializer = [AFJSONRequestSerializer serializer];
    }
    return self;
}

#pragma mark Manager Methods

- (void) queueUnauthenticatedRequest:(TSRequest*) request success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))successCompletionBlock failure: (void (^)(AFHTTPRequestOperation *operation, NSError *error)) failureCompletionBlock{
  AFHTTPRequestOperation *operation = [[AFHTTPRequestOperation alloc] initWithRequest:request];

  [operation  setCompletionBlockWithSuccess:successCompletionBlock failure:failureCompletionBlock];
  [operationManager.operationQueue addOperation:operation ];
}

- (void) queueAuthenticatedRequest:(TSRequest*) request success:(void (^)(AFHTTPRequestOperation *operation, id responseObject))successCompletionBlock failure: (void (^)(AFHTTPRequestOperation *operation, NSError *error)) failureCompletionBlock{
  
   if ([request isKindOfClass:[TSRequestVerificationCodeRequest class]]) {
      // The only unauthenticated request is the initial request for a verification code

        operationManager.requestSerializer = [AFJSONRequestSerializer serializer];
        [operationManager GET:[textSecureServer stringByAppendingString:request.URL.absoluteString]
                   parameters:request.parameters
                      success:successCompletionBlock
                      failure:failureCompletionBlock];
       
    } else if ([request isKindOfClass:[TSServerCodeVerificationRequest class]]){
        // We plant the Authorization parameter ourselves, no need to double add.
        operationManager.requestSerializer = [AFJSONRequestSerializer serializer];
        
        // Take out the Basic Auth Params
        
        [operationManager.requestSerializer setAuthorizationHeaderFieldWithUsername:[TSKeyManager getUsername]
                                                                           password:[request.parameters objectForKey:@"AuthKey"]];
        
        [request.parameters removeObjectForKey:@"AuthKey"];
        
        [operationManager PUT:[textSecureServer stringByAppendingString:request.URL.absoluteString]
                   parameters:request.parameters
                      success:successCompletionBlock
                      failure:failureCompletionBlock];
    }
    else{
        // For all other equests, we do add an authorization header
        operationManager.requestSerializer = [AFJSONRequestSerializer serializer];
        
        [operationManager.requestSerializer setAuthorizationHeaderFieldWithUsername:[TSKeyManager getUsername]
                                                                           password:[TSKeyManager getAuthenticationToken]];
                
        if ([request.HTTPMethod isEqualToString:@"GET"]) {
            [operationManager GET:[textSecureServer stringByAppendingString:request.URL.absoluteString]
                       parameters:request.parameters
                          success:successCompletionBlock
                          failure:failureCompletionBlock];
            
        } else if ([request.HTTPMethod isEqualToString:@"POST"]){
            [operationManager POST:[textSecureServer stringByAppendingString:request.URL.absoluteString]
                        parameters:request.parameters
                           success:successCompletionBlock
                           failure:failureCompletionBlock];
            
        } else if ([request.HTTPMethod isEqualToString:@"PUT"]){
            [operationManager PUT:[textSecureServer stringByAppendingString:request.URL.absoluteString]
                       parameters:request.parameters
                          success:successCompletionBlock
                          failure:failureCompletionBlock];
        }
    }
}


@end
