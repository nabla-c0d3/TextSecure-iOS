//
//  TSContactPickerViewController.m
//  TextSecureiOS
//
//  Created by Frederic Jacobs on 02/02/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import "TSContactPickerViewController.h"
#import "TSContactManager.h"
#import "ComposeMessageViewController.h"
#import "TSThread.h"

#define tableViewCellsDequeID @"TSContactCell"

@interface TSContactPickerViewController ()

@property NSArray *whisperContacts;

@end

@implementation TSContactPickerViewController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        
        [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:YES];
        self.title = @"Loading";
        
        UIBarButtonItem *dismissButton = [[UIBarButtonItem alloc] initWithTitle:@"Dismiss" style:UIBarButtonItemStylePlain target:self action:@selector(dismissVC)];
        self.navigationItem.leftBarButtonItem = dismissButton;
        
        [TSContactManager getAllContactsIDs:^(NSArray *contacts) {   
            [[UIApplication sharedApplication] setNetworkActivityIndicatorVisible:FALSE];
            self.title = @"Pick recepient";
            self.whisperContacts = contacts;
            [self.tableView reloadData];
        }];
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
}

#pragma mark Tableview Delegate Methods

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView{
    return 1;
}

- (NSInteger) tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section{
    return [self.whisperContacts count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath{
    UITableViewCell *cell;
    cell = [tableView dequeueReusableCellWithIdentifier:tableViewCellsDequeID];
    if (!cell) {
        cell = [[UITableViewCell alloc]initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:tableViewCellsDequeID];
    }
    
    TSContact *contact = ((TSContact *)[self.whisperContacts objectAtIndex:indexPath.row]);
        
    cell.textLabel.text = [contact getFullNameFromAddressBook];
    cell.detailTextLabel.text = [contact getUsernameLabelFromAddressBook];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [((UINavigationController*)self.navigationController.presentingViewController) pushViewController:[[ComposeMessageViewController alloc] initWithConversation:[TSThread threadWithContact:[[self.whisperContacts objectAtIndex:indexPath.row] username]]] animated:NO];
    [self dismissViewControllerAnimated:YES
                             completion:nil];
}

- (void) dismissVC {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
