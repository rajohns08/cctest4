//
//  ViewController.m
//  cctest4
//
//  Created by Adam Johns on 4/6/22.
//

#import "ViewController.h"
#import "ccpbkdf2.h"
#import "ccsha2.h"
#import "ccaes.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    // pbkdf2
    const uint8_t *password[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t *salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    size_t passwordLen = sizeof(password)/sizeof(password[0]);
    size_t saltLen = sizeof(salt)/sizeof(salt[0]);
    size_t iterations = 100000;
    size_t dkLen = CCAES_KEY_SIZE_256;
    uint8_t *dk[dkLen];
    const struct ccdigest_info *di = ccsha256_di();
    int rc = ccpbkdf2_hmac(di, passwordLen, password, saltLen, salt, iterations, dkLen, dk);
    uint8_t dk0 = dk[0];
    NSLog(@"test");
    
    // aes encryption
    cccbc_ctx *ctx;
    struct ccmode_cbc test;
    test.size = 4;
    test.block_size = CCAES_BLOCK_SIZE;
    test.init(&test, key, CCAES_KEY_SIZE_256);
}


@end
