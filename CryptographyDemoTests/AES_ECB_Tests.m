#import <XCTest/XCTest.h>
#import "Crypto.h"


@interface AES_ECB_Tests : XCTestCase

@end

@implementation AES_ECB_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_AES_ECB_encrypt_decrypt {
    
    NSData *plaintText = [DataFormatter hexStringToData:@"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"];
    NSData *iv = nil;
    NSData *key = [DataFormatter hexStringToData:@"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"];
    
    // encrypt
    CCOptions pad = 0;
    NSData *encryptedData = [Crypto doCipher:plaintText
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeECB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];

    NSData *expectedAnswer = [DataFormatter hexStringToData:@"F3EED1BD B5D2A03C 064B5A7E 3DB181F8 591CCB10 D410ED26 DC5BA74A 31362870 B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D 23304B7A 39F9F3FF 067D8D8F 9E24ECC7"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeECB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, plaintText);
}


@end
