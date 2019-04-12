#import <XCTest/XCTest.h>
#import "Crypto.h"

// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

#define KEY_ECB128  @"2B7E1516 28AED2A6 ABF71588 09CF4F3C"
#define KEY_ECB192  @"8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B"
#define KEY_ECB256  @"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"

#define plainText  @"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"


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

- (void)testPerformance_AES_EBC_Modes{
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        [self test_AES_ECB_128];
        [self test_AES_ECB_192];
        [self test_AES_ECB_256];
    }];
}

/*
 test vectors:
 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
 */

- (void)test_AES_ECB_128 {
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    
    NSData *iv = nil;
    NSData *key = [DataFormatter hexStringToData:KEY_ECB128];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeECB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"3AD77BB4 0D7A3660 A89ECAF3 2466EF97 F5D3D585 03B9699D E785895A 96FDBAAF 43B1CD7F 598ECE23 881B00E3 ED030688 7B0C785E 27E8AD3F 82232071 04725DD4"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeECB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_AES_ECB_192 {
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    
    NSData *iv = nil;
    NSData *key = [DataFormatter hexStringToData:KEY_ECB192];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeECB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"BD334F1D 6E45F25F F712A214 571FA5CC 97410484 6D0AD3AD 7734ECB3 ECEE4EEF EF7AFD22 70E2E60A DCE0BA2F ACE6444E 9A4B41BA 738D6C72 FB166916 03C18E0E"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeECB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_AES_ECB_256 {
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    
    NSData *iv = nil;
    NSData *key = [DataFormatter hexStringToData:KEY_ECB256];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
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
    
    XCTAssertEqualObjects(decryptedData, msg);
}


@end
