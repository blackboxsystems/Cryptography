#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "TestVectorConstants.h"
/*
    test vectors:
    - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
    - https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
*/
@interface AES_ECB_Tests : XCTestCase

@end

@implementation AES_ECB_Tests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

//- (void)testPerformance_AES_EBC_Modes{
//    // This is an example of a performance test case.
//    [self measureBlock:^{
//        // Put the code you want to measure the time of here.
//        [self test_AES_ECB_128];
//        [self test_AES_ECB_192];
//        [self test_AES_ECB_256];
//    }];
//}

- (void)test_AES_ECB_128
{
    NSData *msg = [DataFormatter hexStringToData:AES_ECB_PLAINTEXT];
    
    NSData *key = [DataFormatter hexStringToData:AES_KEY_ECB128];
    NSData *iv = nil;
    
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

- (void)test_AES_ECB_192
{
    NSData *msg = [DataFormatter hexStringToData:AES_ECB_PLAINTEXT];

    NSData *key = [DataFormatter hexStringToData:AES_KEY_ECB192];
    NSData *iv = nil;
    
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

- (void)test_AES_ECB_256
{
    NSData *msg = [DataFormatter hexStringToData:AES_ECB_PLAINTEXT];

    NSData *key = [DataFormatter hexStringToData:AES_KEY_ECB256];
    NSData *iv = nil;
    
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
