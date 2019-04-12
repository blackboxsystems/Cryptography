#import <XCTest/XCTest.h>
#import "DataFormatter.h"
#import "Crypto.h"

// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

#define KEY_OFB128  @"2B7E1516 28AED2A6 ABF71588 09CF4F3C"
#define KEY_OFB192  @"8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B"
#define KEY_OFB256  @"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"

#define ivec        @"00010203 04050607 08090A0B 0C0D0E0F"

#define plainText  @"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"


@interface AES_OFB_Tests : XCTestCase

@end

@implementation AES_OFB_Tests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

//- (void)testPerformance_AES_OFB_Modes{
//    // This is an example of a performance test case.
//    [self measureBlock:^{
//        // Put the code you want to measure the time of here.
//        [self test_AES_OFB_128];
//        [self test_AES_OFB_192];
//        [self test_AES_OFB_256];
//    }];
//}

/*
 test vectors:
 https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
 */
//- (void)test_AES_OFB_128{
//
//    
//    NSData *msg = [DataFormatter hexStringToData:plainText];
//    NSData *iv = [DataFormatter hexStringToData:ivec];
//    NSData *key = [DataFormatter hexStringToData:KEY_OFB128];
//
//    // encrypt
//    CCOptions pad = ccNoPadding;
//    NSData *encryptedData = [Crypto doCipher:msg
//                                         key:key
//                                     context:kCCEncrypt
//                                        mode:kCCModeOFB
//                                   algorithm:kCCAlgorithmAES
//                                     padding:&pad
//                                          iv:iv];
//
//    NSData *expectedAnswer = [DataFormatter hexStringToData:@"3B3FD92E B72DAD20 333449F8 E83CFB4A C8A64537 A0B3A93F CDE3CDAD 9F1CE58B 26751F67 A3CBB140 B1808CF1 87A4F4DF C04B0535 7C5D1C0E EAC4C66F 9FF7F2E6"];
//    XCTAssertEqualObjects(encryptedData, expectedAnswer);
//
//    // decrypt
//    NSData *decryptedData = [Crypto doCipher:encryptedData
//                                         key:key
//                                     context:kCCDecrypt
//                                        mode:kCCModeOFB
//                                   algorithm:kCCAlgorithmAES
//                                     padding:&pad
//                                          iv:iv];
//
//    XCTAssertEqualObjects(decryptedData, msg);
//}
- (void)test_AES_OFB_192{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_OFB192];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"CDC80D6F DDF18CAB 34C25909 C99A4174 FCC28B8D 4C63837C 09E81700 C1100401 8D9A9AEA C0F6596F 559C6D4D AF59A5F2 6D9F2008 57CA6C3E 9CAC524B D9ACC92A"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}
- (void)test_AES_OFB_256{
    
    
    NSData *msg = [DataFormatter hexStringToData:plainText];
    NSData *iv = [DataFormatter hexStringToData:ivec];
    NSData *key = [DataFormatter hexStringToData:KEY_OFB256];
    
    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"DC7E84BF DA79164B 7ECD8486 985D3860 4FEBDC67 40D20B3A C88F6AD8 2A4FB08D 71AB47A0 86E86EED F39D1C5B BA97C408 0126141D 67F37BE8 538F5A8B E740E484"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, msg);
}

@end
