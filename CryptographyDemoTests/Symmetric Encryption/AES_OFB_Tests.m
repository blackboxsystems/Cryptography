#import <XCTest/XCTest.h>
#import "DataFormatter.h"
#import "Crypto.h"
#import "TestVectorConstants.h"
/*
    test vectors:
     - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
     - https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
*/
@interface AES_OFB_Tests : XCTestCase

@end

@implementation AES_OFB_Tests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
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

- (void)test_AES_OFB_128
{
    NSData *msg = [DataFormatter hexStringToData:AES_OFB_PLAINTEXT];
    
    NSData *iv = [DataFormatter hexStringToData:AES_IV_OFB];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_OFB128];

    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"3B3FD92E B72DAD20 333449F8 E83CFB4A 7789508D 16918F03 F53C52DA C54ED825 9740051E 9C5FECF6 4344F7A8 2260EDCC 304C6528 F659C778 66A510D9 C1D6AE5E"];
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
- (void)test_AES_OFB_192
{
    NSData *msg = [DataFormatter hexStringToData:AES_OFB_PLAINTEXT];
 
    NSData *iv = [DataFormatter hexStringToData:AES_IV_OFB];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_OFB192];
    
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

- (void)test_AES_OFB_256
{
    NSData *msg = [DataFormatter hexStringToData:AES_OFB_PLAINTEXT];
 
    NSData *iv = [DataFormatter hexStringToData:AES_IV_OFB];
    NSData *key = [DataFormatter hexStringToData:AES_KEY_OFB256];
    
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


- (void)test_AES_OFB_128_blank_message
{
    NSData *msg = [DataFormatter hexStringToData:BLANK_PLAINTEXT_32];
 
    NSData *iv = [DataFormatter hexStringToData:AES_IV_OFB01];
    NSData *iv2 = [DataFormatter hexStringToData:AES_IV_OFB02];
    
    NSData *key = [DataFormatter hexStringToData:AES_KEY_OFB128_0];
    NSData *key2 = [DataFormatter hexStringToData:AES_KEY_OFB128_1];

    // encrypt
    CCOptions pad = ccNoPadding;
    NSData *encryptedData = [Crypto doCipher:msg
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *encryptedData2 = [Crypto doCipher:msg
                                          key:key2
                                      context:kCCEncrypt
                                         mode:kCCModeOFB
                                    algorithm:kCCAlgorithmAES
                                      padding:&pad
                                           iv:iv2];
    
    NSData *combinedEncryption = [Crypto xorData:encryptedData withData:encryptedData2];
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:combinedEncryption
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeOFB
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *decryptedData2 = [Crypto doCipher:decryptedData
                                          key:key2
                                      context:kCCDecrypt
                                         mode:kCCModeOFB
                                    algorithm:kCCAlgorithmAES
                                      padding:&pad
                                           iv:iv2];
    
    XCTAssertEqualObjects(decryptedData2, msg);
}


@end
