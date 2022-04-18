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
    const uint8_t password[] = {0x02, 0x03, 0x04, 0x05};
    uint8_t p0 = password[0];
    NSLog(@"p0: %d", p0);
    const uint8_t salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    size_t passwordLen = sizeof(password)/sizeof(password[0]);
    size_t saltLen = sizeof(salt)/sizeof(salt[0]);
    size_t iterations = 100000;
    size_t dkLen = CCAES_KEY_SIZE_256;
    uint8_t dk[dkLen];
    const struct ccdigest_info *di = ccsha256_di();
    int rc = ccpbkdf2_hmac(di, passwordLen, password, saltLen, salt, iterations, dkLen, dk);
    uint8_t dk0 = dk[0];
    NSLog(@"dk0: %d", dk0);
    
    // aes encryption
    uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01};
    size_t dataLen = sizeof(data)/sizeof(data[0]);
    size_t nblocks = ceil((double)dataLen/CCAES_BLOCK_SIZE);
    int rcode;
    const struct ccmode_cbc *mode = ccaes_cbc_encrypt_mode();
    
    uint8_t encryptedData[nblocks*mode->block_size];
    cccbc_ctx_decl(mode->size, ctx);
    cccbc_iv_decl(mode->block_size, iv_ctx);
    cc_clear(mode->block_size, iv_ctx);
    rcode = mode->init(mode, ctx, CCAES_KEY_SIZE_256, dk);
    mode->cbc(ctx, iv_ctx, nblocks, data, encryptedData);
    uint8_t ed0 = encryptedData[0];
    uint8_t ed1 = encryptedData[1];
    uint8_t ed2 = encryptedData[2];
    uint8_t ed3 = encryptedData[3];
    uint8_t ed4 = encryptedData[4];
    uint8_t ed5 = encryptedData[5];
    uint8_t ed6 = encryptedData[6];
    uint8_t ed7 = encryptedData[7];
    uint8_t ed8 = encryptedData[8];
    uint8_t ed9 = encryptedData[9];
    uint8_t ed10 = encryptedData[10];
    uint8_t ed11 = encryptedData[11];
    uint8_t ed12 = encryptedData[12];
    uint8_t ed13 = encryptedData[13];
    uint8_t ed14 = encryptedData[14];
    uint8_t ed15 = encryptedData[15];
    uint8_t ed16 = encryptedData[16];
    NSLog(@"ed0: %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d", ed0, ed1, ed2, ed3, ed4, ed5, ed6, ed7, ed8, ed9, ed10, ed11, ed12, ed13, ed14, ed15, ed16);
    cccbc_ctx_clear(mode->size, ctx);
    
    
    // aes decryption
    const struct ccmode_cbc *decrypt_mode = ccaes_cbc_decrypt_mode();
    uint8_t decrypted_data[nblocks*decrypt_mode->block_size];
    cccbc_ctx_decl(decrypt_mode->size, dctx);
    cccbc_iv_decl(decrypt_mode->block_size, div_ctx);
    cc_clear(decrypt_mode->block_size, div_ctx);
    int dcode;
    dcode = decrypt_mode->init(decrypt_mode, dctx, CCAES_KEY_SIZE_256, dk);
    decrypt_mode->cbc(dctx, div_ctx, nblocks, encryptedData, decrypted_data);
    uint8_t dd0 = decrypted_data[0];
    uint8_t dd1 = decrypted_data[1];
    uint8_t dd2 = decrypted_data[2];
    uint8_t dd3 = decrypted_data[3];
    uint8_t dd4 = decrypted_data[4];
    uint8_t dd5 = decrypted_data[5];
    uint8_t dd6 = decrypted_data[6];
    uint8_t dd7 = decrypted_data[7];
    uint8_t dd8 = decrypted_data[8];
    uint8_t dd9 = decrypted_data[9];
    uint8_t dd10 = decrypted_data[10];
    uint8_t dd11 = decrypted_data[11];
    uint8_t dd12 = decrypted_data[12];
    uint8_t dd13 = decrypted_data[13];
    uint8_t dd14 = decrypted_data[14];
    uint8_t dd15 = decrypted_data[15];
    uint8_t dd16 = decrypted_data[16];
    NSLog(@"dd0: %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d", dd0, dd1, dd2, dd3, dd4, dd5, dd6, dd7, dd8, dd9, dd10, dd11, dd12, dd13, dd14, dd15, dd16);
    
}


@end
