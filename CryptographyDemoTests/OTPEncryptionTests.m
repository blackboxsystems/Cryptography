#import <XCTest/XCTest.h>
#import "Protocol.h"
#import "OTPCrypto.h"
#import "Crypto.h"
#import "Mnemonic.h"

#define kDEFAULT_PASSWORD @"testing123"

#define mnemonic12      @"color install recipe clown empty bind safe what dream fat move grow"
#define mnemonic24      @"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"

#define mnemonic48      @"meadow street risk direct describe volume cruel absent flat upset among equip coast struggle flat process bounce verify genius pyramid step extra husband belt pencil nature crucial host rate distance series delay skirt wait toward turtle motion session cross play custom sheriff convince hover carry drip health combine"

#define kSalt512    @"89badee99f43b9eb8d2005589de41fa612cdae96255c1a7e5583d78d56a21bf8a7a2b26cd1b70b227f7101cfcabecf98757905888d05323698b0be37322e865a"

@interface OTPEncryptionTests : XCTestCase

@end

@implementation OTPEncryptionTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    [super tearDown];
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

#pragma mark - DETERMINISTIC ONE TIME PAD PROOF - DIFFICULTY BASED
- (void)test_ONE_TIME_PAD_PROTOCOL_DIFFICULTY_LOW {
    
    NSData *plaintext = [Mnemonic entropyFromMemnonic:mnemonic24];
    NSData *salt = [DataFormatter hexStringToData:kSalt512];
    
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
- (void)test_ONE_TIME_PAD_PROTOCOL_TIMED {
    
    // target time in seconds for pad generation
    double targetSeconds = 5.0;
    NSData *plaintext = [Mnemonic entropyFromMemnonic:mnemonic24];
    NSData *salt = [DataFormatter hexStringToData:kSalt512];
    
    // encypted pad data
    NSData *blob = [OTPCrypto deriveTimedOTP:kDEFAULT_PASSWORD
                                        salt:salt
                                        data:plaintext
                                     padTime:kMSEC_IN_SEC*targetSeconds
                                      rounds:0
                                     encrypt:YES];
    
    // parse parameters to check decryption
    NSDictionary *parsedOTPBlob = [Protocol parseBlob:blob];
//    NSLog(@"\nparsed Timed OTP Blob: %@",parsedOTPBlob);
    NSData *parsed_salt = [DataFormatter hexStringToData:[parsedOTPBlob objectForKey:PROTOCOL_SALT_KEY]];
    NSInteger parsed_rounds = [[parsedOTPBlob objectForKey:PROTOCOL_ROUNDS_KEY] integerValue];
    NSData *parsed_blob = [DataFormatter hexStringToData:[parsedOTPBlob objectForKey:PROTOCOL_BLOB_KEY]];
    
    // decrypt and check
    NSData *decrypted_pad = [OTPCrypto deriveTimedOTP:kDEFAULT_PASSWORD
                                                 salt:parsed_salt
                                                 data:parsed_blob
                                              padTime:0.0
                                               rounds:parsed_rounds
                                              encrypt:NO];
    
    XCTAssertEqualObjects(decrypted_pad, plaintext);
}

@end
