#import <XCTest/XCTest.h>
#import "Crypto.h"
#import "Mnemonic.h"
#import "TestVectorConstants.h"

@interface CryptographyDemoTests : XCTestCase

@end

@implementation CryptographyDemoTests


- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


- (void)test_encryptDecrypt_Blob
{    
    NSData *msg = [Mnemonic entropyFromMemnonic:kDEFAULT_MNEMONIC_12];
    NSData *salt = [DataFormatter hexStringToData:kDEFAULT_SALT_512];
    NSInteger kdf_rounds = kKDFRoundsTEST;
    NSString *password = kDEFAULT_PASSWORD;
    
    // derive
    NSData *key = [Crypto deriveKey:password
                               salt:salt
                               mode:masterKey
                             rounds:kdf_rounds];
    
    // split derived key
    NSData *Kx = [key subdataWithRange:NSMakeRange(0, kAES256_KEY_LENGTH_BYTES)];
    NSData *Ky = [key subdataWithRange:NSMakeRange(kAES256_KEY_LENGTH_BYTES, kAES256_KEY_LENGTH_BYTES)];
    
    // encrypt-then-mac
    NSData *encryptedBlob = [Crypto encryptThenMAC:msg
                                            encKey:Kx
                                            intKey:Ky];
    
    // construct protocol data (public params and encrypted blob)
    NSData *protocol = [Protocol createProtocolWithBlob:encryptedBlob
                                                kdfMode:masterKey
                                                encMode:BBEncryptAES
                                                   salt:salt
                                                 rounds:kdf_rounds];
    
    // parse, decode, and decrypt to verify
    NSDictionary *parsedProtocol = [Protocol parseBlob:protocol];
    XCTAssertNotNil(parsedProtocol);
    
    NSInteger parsed_kdfmode = [parsedProtocol[PROTOCOL_KDF_MODE_KEY] integerValue];
    // not needed here but can allow abstraction for other implementations
//    int encmode = [parsedProtocol[PROTOCOL_ENCRYPTION_MODE_KEY] integerValue];
    NSInteger parsed_rounds = [parsedProtocol[PROTOCOL_ROUNDS_KEY] integerValue];
    NSInteger parsed_version = [parsedProtocol[PROTOCOL_VERSION_KEY] integerValue];
    NSData *parsed_salt = [DataFormatter hexStringToData:parsedProtocol[PROTOCOL_SALT_KEY]];
    NSData *parsed_blob = [DataFormatter hexStringToData:parsedProtocol[PROTOCOL_BLOB_KEY]];
    
    XCTAssertTrue(parsed_version == APP_PROTOCOL_VERSION);
    XCTAssertTrue(parsed_rounds == kdf_rounds);
    XCTAssertEqualObjects(parsed_salt, salt);
    XCTAssertEqualObjects(parsed_blob, encryptedBlob);
    
    NSData *key2 = [Crypto deriveKey:password
                                salt:parsed_salt
                                mode:parsed_kdfmode
                              rounds:parsed_rounds];
    
    XCTAssertEqualObjects(key2, key);
    
    Kx = [key2 subdataWithRange:NSMakeRange(0, kAES256_KEY_LENGTH_BYTES)];
    Ky = [key2 subdataWithRange:NSMakeRange(kAES256_KEY_LENGTH_BYTES, kAES256_KEY_LENGTH_BYTES)];
    
    NSData *decryptedData = [Crypto decryptWithMAC:parsed_blob encKey:Kx intKey:Ky];
    XCTAssertEqualObjects(decryptedData, msg);
}

- (void)test_proofOfWork
{
    // init challenge
    NSData *challenge = [DataFormatter hexStringToData:@"ab436ff422f54c852829a63ab325791c001de60ae4ea934ad8a603cc5eab3129"];
    // number of leading 0's to find
    NSInteger difficulty = 4;
    
    NSDictionary *dict = [Crypto proofOfWork:challenge difficulty:difficulty];
    NSString *proof = [DataFormatter hexDataToString:[dict objectForKey:@"proof"]];
    NSInteger nonce = [[dict objectForKey:@"nonce"] integerValue];
    
    // verify proof parameters
    XCTAssertEqual(nonce, 35559);
    XCTAssertEqualObjects(proof, @"000024b20de5f9375254af627f76c47fa93973f3442bfbe42e9fc8fd9cc969c6");
}


@end
