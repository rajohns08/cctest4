//
//  ViewController.m
//  cctest4
//
//  Created by Adam Johns on 4/6/22.
//

#import "ViewController.h"
#import "cczp.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    struct cczp mystruct;
    int test = cczp_init(&mystruct);
}


@end
