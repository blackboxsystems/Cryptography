#import <XCTest/XCTest.h>
#import "Crypto.h"


@interface AES_CBC_Tests : XCTestCase

@end

@implementation AES_CBC_Tests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)test_AES_CBC_Mode{
    
    NSData *plaintText = [DataFormatter hexStringToData:@"6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710"];    
    NSData *iv = [DataFormatter hexStringToData:@"00010203 04050607 08090A0B 0C0D0E0F"];
    NSData *key = [DataFormatter hexStringToData:@"603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4"];
    
    // encrypt
    CCOptions pad = 0;
    NSData *encryptedData = [Crypto doCipher:plaintText
                                         key:key
                                     context:kCCEncrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    NSData *expectedAnswer = [DataFormatter hexStringToData:@"F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6 9CFC4E96 7EDB808D 679F777B C6702C7D 39F23369 A9D9BACF A530E263 04231461 B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B"];
    XCTAssertEqualObjects(encryptedData, expectedAnswer);
    
    // decrypt
    NSData *decryptedData = [Crypto doCipher:encryptedData
                                         key:key
                                     context:kCCDecrypt
                                        mode:kCCModeCBC
                                   algorithm:kCCAlgorithmAES
                                     padding:&pad
                                          iv:iv];
    
    XCTAssertEqualObjects(decryptedData, plaintText);
}

@end
