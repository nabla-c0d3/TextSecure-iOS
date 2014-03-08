//
//  VerificationViewController.m
//  TextSecureiOS
//
//  Created by Christine Corbett Moran on 3/24/13.
//  Copyright (c) 2013 Open Whisper Systems. All rights reserved.
//

#import "VerificationViewController.h"
#import "TSKeyManager.h"
@interface VerificationViewController ()

@end

@implementation VerificationViewController
// Note there are so many IBOutlets to support easy Localizable.strings localization
// and customization of fonts. Hopefully this will be made easier in the future iOS dev
// suite to be done entirely via Storyboards and not via code. If anyone has a cleaner way
// of doing this, please go ahead.
@synthesize phoneNumber;

@synthesize countryName;
@synthesize countryCodeInput;
@synthesize explanationText;

#pragma mark View Controller Methods

- (void)viewDidLoad {
	[super viewDidLoad];
	// Do any additional setup after loading the views
    
	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(countryChosen:) name:@"CountryChosen" object:nil];
	[countryCodeInput addTarget:self action:@selector(updateCountryCode:) forControlEvents:UIControlEventEditingChanged];
    
    UIBarButtonItem *nextButton = [[UIBarButtonItem alloc] initWithTitle:@"Next" style:UIBarButtonItemStylePlain target:self action:@selector(sendVerification:)];
    
    self.navigationItem.rightBarButtonItem = nextButton;
    [self.navigationItem.rightBarButtonItem setEnabled:NO];
    
    self.navigationItem.title = @"Your Phone Number";
    
    [self setLocaleCountry];
    
    [self.phoneNumber becomeFirstResponder];
    
}

- (void) viewDidAppear:(BOOL)animated{
    // If user comes back to this page, make him re-enter all data.
    [TSKeyManager removeAllKeychainItems];
}

#pragma mark Phone number formatting
// Based on the user's locale we are guessing what his country code would be.

-(void) initNumberFormatter{
    self.numberFormatter = [[NBAsYouTypeFormatter alloc]initWithRegionCode:[NSLocale localizedCodeNameForPhonePrefix:[self.countryCodeInput.text removeAllFormattingButNumbers]]];
    
    NSString *charString = [[countryCodeInput.text removeAllFormattingButNumbers] prependPlus];
    
    for (int i = 0; i < charString.length; i++) {
        [self.numberFormatter inputDigit:[charString substringWithRange:NSMakeRange(i, 1)]];
    }
}

-(void)setLocaleCountry{
    DLog(@"Setting Locale to : %@", [[NSLocale currentLocale] objectForKey:NSLocaleCountryCode]);
    
    self.countryCodeInput.text = [NSLocale currentCountryPhonePrefix];
    [self updateCountryCode:nil];
}

-(void)updateCountryCode:(id)sender {
    NSString *enteredCountryCode = self.countryCodeInput.text;
    enteredCountryCode = [enteredCountryCode removeAllFormattingButNumbers];
    
    [self updateCountry:@{@"country_code":enteredCountryCode, @"name":[[NSLocale currentLocale] displayNameForKey:NSLocaleCountryCode value:[NSLocale localizedCodeNameForPhonePrefix:enteredCountryCode]]}];
}

-(void)updateCountry:(NSDictionary*)countryInfo {
	self.countryCodeInput.text = [[countryInfo objectForKey:@"country_code"] prependPlus];
	self.countryName.text=[countryInfo objectForKey:@"name"];
}

-(void) countryChosen:(NSNotification*)notification {
	[self updateCountry:[notification userInfo]];
}

#pragma mark - Verification Action

-(void)sendVerification:(id)sender {
    self.selectedPhoneNumber = [NSString stringWithFormat:@"%@%@",self.countryCodeInput.text,[self.phoneNumber.text removeAllFormattingButNumbers]];
    [[TSNetworkManager sharedManager] queueAuthenticatedRequest:[[TSRequestVerificationCodeRequest alloc] initRequestForPhoneNumber:self.selectedPhoneNumber transport:kSMSVerification] success:^(AFHTTPRequestOperation *operation, id responseObject){
        
        DLog(@"Requested confirmation code : %@ for code :%i", responseObject, operation.response.statusCode);
        
        [TSKeyManager storeUsername:self.selectedPhoneNumber];
        
        [TSKeyManager generateNewAccountAuthenticationToken];
        [TSKeyManager generateNewSignalingKeyToken];
        
        [self performSegueWithIdentifier:@"ConfirmVerificationCode" sender:self];
        
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        [[[UIAlertView alloc]initWithTitle:@"Sorry we had an issue with this request" message:@"Read Dlog" delegate:nil cancelButtonTitle:@"Ok" otherButtonTitles:nil, nil] show];
    }];
}

#pragma mark Formatted Number String processing

- (BOOL)textFieldShouldBeginEditing:(UITextField *)textField{
    
    if ([textField isEqual:self.countryCodeInput]) {
        self.countryCodeInput.text = @"+";
        [self updateCountryCode:nil];
    } else if ([textField isEqual:self.phoneNumber]){
        [self initNumberFormatter];
    }
    
    return YES;
}

- (BOOL)textField:(UITextView *)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString *)string{
	
    if ([textField isEqual:self.countryCodeInput]) {
        NSUInteger newLength = (textField.text.length - range.length) + string.length;
        if(newLength < 4) {
            return YES;
        } else {
            NSUInteger emptySpace = 4 - (textField.text.length - range.length);
            textField.text = [[[textField.text substringToIndex:range.location]
                               stringByAppendingString:[string substringToIndex:emptySpace]]
                              stringByAppendingString:[textField.text substringFromIndex:(range.location + range.length)]];
            [self.phoneNumber becomeFirstResponder];
            [self updateCountryCode:nil];
            return NO;
        }
        
    } else if ([textField isEqual:self.phoneNumber]){
        
        // A character is deleted. We rebuild the formatter with one fewer char
        [self initNumberFormatter];
        
        NSString *formattedString;
        
        NSString *nonFormattedstring = [self.phoneNumber.text removeAllFormattingButNumbers];
        
        // The last added character might not be at the end of the string
        
        int loopLength = nonFormattedstring.length+1;
        
        if ([string isEqualToString:@""]) {
            loopLength = nonFormattedstring.length;
        }
        
        for (int i = 0; i < loopLength; i++) {
            if (i != ([self location:range.location ofCleanedStringOf:self.phoneNumber.text])) {
                formattedString = [self.numberFormatter inputDigit:[nonFormattedstring substringWithRange:NSMakeRange(i, 1)]];
            } else {
                // if we are at the replace or add position, we need to evaluate what to do
                
                if ([string isEqualToString:@""]) {
                    // This is the character added to remove chars, there is nothing to do
                }
                else{
                    formattedString = [self.numberFormatter inputDigit:string];
                }
            }
        }
        
        self.phoneNumber.text = [self cleanPrefixOfString:formattedString];
        
        
        // We detect if the number is a valid number. If it is, we show the next button.
        
        NSError *error = nil;
        
        NBPhoneNumber *number = [[NBPhoneNumberUtil sharedInstance] parse:[self.countryCodeInput.text stringByAppendingString:self.phoneNumber.text] defaultRegion:[NSLocale localizedCodeNameForPhonePrefix:self.countryCodeInput.text] error:&error];
        
        if (error == nil && [[NBPhoneNumberUtil sharedInstance] isValidNumber:number]) {
            self.navigationItem.rightBarButtonItem.enabled = TRUE;
        } else{
            self.navigationItem.rightBarButtonItem.enabled = FALSE;
        }
        
        return NO;
        
    } else {
        return YES;
    }
}

// The parsing library needs to see the phone number with the prefix, we do show it without it.
// This ugly method clean the prefix so that phone number fields is parsed but without prefix.

-(NSString*) cleanPrefixOfString:(NSString*)formattedText{
    
    NSMutableArray *prefix = [NSMutableArray array];
    NSString *prefixString = [[countryCodeInput.text removeAllFormattingButNumbers] prependPlus];
    
    for (int i = 0; i < prefixString.length; i++) {
        [prefix addObject:[prefixString substringWithRange:NSMakeRange(i, 1)]];
    }
    
    int lastCharLoc = 0;
    
    for (int i = 0; i < formattedText.length; i++) {
        if ([[formattedText substringWithRange:NSMakeRange(i, 1)] isEqualToString:[prefix firstObject]]) {
            [prefix removeObjectAtIndex:0];
            
            if (prefix.count == 0) {
                lastCharLoc = i;
            }
        }
    }
    
    if (lastCharLoc < formattedText.length) {
        if (!isnumber([formattedText characterAtIndex:(lastCharLoc+1)])) {
            lastCharLoc++;
        }
    }
    
    return [formattedText substringWithRange:NSMakeRange(lastCharLoc+1, formattedText.length-(lastCharLoc+1))];
}

-(int) location:(int)loc ofCleanedStringOf:(NSString*)string{
    NSString *cleanedString = [string removeAllFormattingButNumbers];
    
    NSMutableArray *prefix = [NSMutableArray array];
    
    for (int i = 0; i < cleanedString.length; i++) {
        [prefix addObject:[cleanedString substringWithRange:NSMakeRange(i, 1)]];
    }
    
    int cleanedStringIndex = 0;
    
    for (int i = 0; i < loc; i++) {
        if ([[string substringWithRange:NSMakeRange(i, 1)] isEqualToString:[prefix objectAtIndex:cleanedStringIndex]]) {
            cleanedStringIndex++;
        }
    }
    return cleanedStringIndex;
}

#pragma mark Memory allocations

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
