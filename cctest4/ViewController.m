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
    uint8_t data[] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    size_t dataLen = sizeof(data)/sizeof(data[0]);
    int rcode;
    const struct ccmode_cbc *mode = ccaes_cbc_encrypt_mode();
    
    uint8_t *encryptedData[dataLen + CCAES_BLOCK_SIZE];
    cccbc_ctx_decl(mode->size, ctx);
    cccbc_iv_decl(mode->block_size, iv_ctx);
    cc_clear(mode->block_size, iv_ctx);
    rcode = mode->init(mode, ctx, CCAES_KEY_SIZE_256, dk);
    mode->cbc(ctx, iv_ctx, dataLen, &data, encryptedData);
    uint8_t ed0 = encryptedData[0];
    cccbc_ctx_clear(mode->size, ctx);
    NSLog(@"rcode: %d", rcode);
}


@end
