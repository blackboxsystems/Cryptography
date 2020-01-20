#import <XCTest/XCTest.h>
#import "OTPCrypto.h"
#import "Mnemonic.h"
#import "TestVectorConstants.h"

@interface OTPEncryptionTests : XCTestCase

@end

@implementation OTPEncryptionTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark - DETERMINISTIC ONE TIME PAD PROOF - DIFFICULTY BASED
- (void)test_ONE_TIME_PAD_PROTOCOL_DIFFICULTY_LOW
{
    NSData *plaintext = [Mnemonic entropyFromMemnonic:kDEFAULT_MNEMONIC_24];
    NSData *salt = [DataFormatter hexStringToData:kDEFAULT_SALT_512];
    
    // encypted pad data
    NSData *pad = [OTPCrypto deriveOTP:kDEFAULT_PASSWORD
                                  salt:salt
                                  data:plaintext
                                rounds:kPBKDFRoundsDefault
                            difficulty:4
                               encrypt:YES];
    
    // parse to decrypt
    NSDictionary *parsedOTPBlob = [Protocol parseBlob:pad];
//    NSLog(@"\nparsedOTPBlob: %@",parsedOTPBlob);
    NSData *parsed_salt = [DataFormatter hexStringToData:[parsedOTPBlob objectForKey:PROTOCOL_SALT_KEY]];
    NSInteger parsed_rounds = [[parsedOTPBlob objectForKey:PROTOCOL_ROUNDS_KEY] integerValue];
    NSInteger parsed_difficulty = [[parsedOTPBlob objectForKey:PROTOCOL_DIFFICULTY_KEY] integerValue];
    NSData *parsed_blob = [DataFormatter hexStringToData:[parsedOTPBlob objectForKey:PROTOCOL_BLOB_KEY]];

    // decrypt and check
    NSData *decrypted_pad = [OTPCrypto deriveOTP:kDEFAULT_PASSWORD
                                            salt:parsed_salt
                                            data:parsed_blob
                                          rounds:parsed_rounds
                                      difficulty:parsed_difficulty
                                         encrypt:NO];

    XCTAssertEqualObjects(decrypted_pad, plaintext);
}


#pragma mark - DETERMINISTIC ONE TIME PAD PROOF - TIME BASED
- (void)test_ONE_TIME_PAD_PROTOCOL_TIMED
{
    // target time in seconds for pad generation
    double targetSeconds = 2.0;
    NSData *plaintext = [Mnemonic entropyFromMemnonic:kDEFAULT_MNEMONIC_24];
    NSData *salt = [DataFormatter hexStringToData:kDEFAULT_SALT_512];
    
    // encypted pad data
    NSData *blob = [OTPCrypto deriveTimedOTP:kDEFAULT_PASSWORD
                                        salt:salt
                                        data:plaintext
                                     padTime:kMSEC_IN_SEC*targetSeconds
                                      rounds:0
                                 blockRounds:0
                                     encrypt:YES];
    
    // parse parameters to check decryption
    NSDictionary *parsedOTPBlob = [Protocol parseBlob:blob];
//    NSLog(@"\nparsed Timed OTP Blob: %@",parsedOTPBlob);
    
    NSData *parsed_salt = [DataFormatter hexStringToData:[parsedOTPBlob objectForKey:PROTOCOL_SALT_KEY]];
    NSInteger parsed_rounds = [[parsedOTPBlob objectForKey:PROTOCOL_ROUNDS_KEY] integerValue];
    NSInteger parsed_round_blocks = [[parsedOTPBlob objectForKey:PROTOCOL_BLOCK_ROUNDS_KEY] integerValue];
    NSData *parsed_blob = [DataFormatter hexStringToData:[parsedOTPBlob objectForKey:PROTOCOL_BLOB_KEY]];
    
    // decrypt and check
    NSData *decrypted_pad = [OTPCrypto deriveTimedOTP:kDEFAULT_PASSWORD
                                                 salt:parsed_salt
                                                 data:parsed_blob
                                              padTime:0.0
                                               rounds:parsed_rounds
                                          blockRounds:parsed_round_blocks
                                              encrypt:NO];
    
    XCTAssertEqualObjects(decrypted_pad, plaintext);
}

@end
