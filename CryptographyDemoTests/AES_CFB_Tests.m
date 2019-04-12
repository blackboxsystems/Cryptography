#import <XCTest/XCTest.h>
#import "Crypto.h"

// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

#define KEY_ECB128  @"2B7E1516 28AED2A6 ABF71588 09CF4F3C"
#define KEY_ECB192  @"8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B"
#define KEY_ECB256  @"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"

#define ivec        @"00010203 04050607 08090A0B 0C0D0E0F"

#define plainText  @"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"

@interface AES_CFB_Tests : XCTestCase

@end

@implementation AES_CFB_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPerformance_AES_CFB_Modes{
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        [self test_AES_CFB_128];
        [self test_AES_CFB_192];
        [self test_AES_CFB_256];
    }];
}

/*
 test vectors:
 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
 */
- (void)test_AES_CFB_128{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_ECB128];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"3B3FD92E B72DAD20 333449F8 E83CFB4A C8A64537 A0B3A93F CDE3CDAD 9F1CE58B 26751F67 A3CBB140 B1808CF1 87A4F4DF C04B0535 7C5D1C0E EAC4C66F 9FF7F2E6"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CFB_192{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_ECB192];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"CDC80D6F DDF18CAB 34C25909 C99A4174 67CE7F7F 81173621 961A2B70 171D3D7A 2E1E8A1D D59B88B1 C8E60FED 1EFAC4C9 C05F9F9C A9834FA0 42AE8FBA 584B09FF"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_CFB_256{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_ECB256];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"DC7E84BF DA79164B 7ECD8486 985D3860 39FFED14 3B28B1C8 32113C63 31E5407B DF101324 15E54B92 A13ED0A8 267AE2F9 75A38574 1AB9CEF8 2031623D 55B1E471"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}


@end

