#import <XCTest/XCTest.h>
#import "KeychainWrapperMock.h"
#import "Crypto.h"

@interface AsymmetricKeyTests : XCTestCase

@end

@implementation AsymmetricKeyTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - ECC TESTS
- (void)test_createECCKeyToSignAndVerifyMessage{
    
    OSStatus status = noErr;
    (void)[KeychainWrapperMock deleteECCKeyPair_TEST];
    
    // init message to sign
    NSString *msg = @"hello world";
    NSData *digest = [Crypto sha256:[msg dataUsingEncoding:NSUTF8StringEncoding]];
    
    // create keys
    status = [KeychainWrapperMock createRandomECCKey_TEST];
    XCTAssertEqual(status, errSecSuccess);
    
    // sign the digest
    NSData *signature_data = [KeychainWrapperMock createECCDigitalSignature_TEST:digest];
    
    // verify the signature
    BOOL valid_sig = [KeychainWrapperMock verifyECCDigitalSignature_TEST:digest signature:signature_data];
    XCTAssertTrue(valid_sig);
    
    // delete the key
    status = [KeychainWrapperMock deleteECCKeyPair_TEST];
    XCTAssertEqual(status, errSecSuccess);
}

@end
