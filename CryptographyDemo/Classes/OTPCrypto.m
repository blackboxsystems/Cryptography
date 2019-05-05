#import "OTPCrypto.h"
#import "Crypto.h"
#import "Timer.h"

@implementation OTPCrypto


#pragma mark - DETERMINISTIC ONE TIME PAD PROOF BASED ENCRYPTION
/**
 Deterministic One-Time-Pad implementation that uses password derived keys and proof of work
 to generate high entropy pad data for encryption and decryption of plaintext.  Strength is based on difficulty,
 entropy of input, password strength, number of blocks, and other parameter qualities.

 @param seed secret input (password)
 @param salt public salt entropy for kdf
 @param plaintext data to encrypt
 @param rounds number of kdf iterations to derive key
 @param diff difficulty measured in number of leading hex characters with leading zeros
 @param encrypt flag for ancrypting vs. decrypting
 @return pad data (encrypted data using otp or decrypted plaintext based on encrypt flag)
 */
+ (NSData *)deriveOTP:(NSString *)seed
                 salt:(NSData *)salt
                 data:(NSData *)plaintext
               rounds:(NSInteger)rounds
           difficulty:(NSInteger)diff
              encrypt:(BOOL)encrypt{
        
//    NSDate *methodStart = [NSDate date];
    BBKDFMode otpMode = otp512;
    
    // derive an initial symmetric key
    NSData *derivedKey = [Crypto deriveKey:seed
                                      salt:salt
                                      mode:otpMode
                                    rounds:rounds];
    
//    double totalExecutionTime = -[Timer computeTimeInterval:methodStart];
    
    // calculate number of blocks for the pad
    NSInteger blocks = 1;
    NSInteger mbytes = derivedKey.length/2;
    NSInteger dataLength = plaintext.length;
    
    if (dataLength > mbytes) {
        blocks = floor(dataLength / mbytes) + (dataLength % mbytes > 0 ? 1 : 0);
    }
    
    // split derived root key (2x32 symmetric keys)
    NSInteger blockSize = derivedKey.length/2;
    NSData *Kek = [derivedKey subdataWithRange:NSMakeRange(0, blockSize)];
    NSData *Kak = [derivedKey subdataWithRange:NSMakeRange(blockSize, blockSize)];
    
    // hash split keys
    NSData *Kx = [Crypto sha256:Kek];
    NSData *Ky = [Crypto sha256:Kak];
    
    NSData *rootKey = [Crypto hmac:Kx key:Ky nbits:Kx.length];
    NSMutableData *rootPad = [[NSMutableData alloc] init];
    NSData *padKey = [Crypto sha256:rootKey];
    
    if (diff == 0) {
        diff = 1;
    }
    
    NSInteger nonceTotal = 0;
    
    // proof-of-work pad generation
    for (NSInteger i = 0; i < blocks; i++)
    {
        // do work
        NSDictionary *dict = [Crypto proofOfWork:padKey difficulty:diff];
        NSData *challenge = [dict objectForKey:@"challenge"];
        NSData *hashedProof = [Crypto sha256:[dict objectForKey:@"proof"]];
        
        // proof properties
//        totalExecutionTime += [[dict objectForKey:@"time"] doubleValue];
        nonceTotal += [[dict objectForKey:@"nonce"] integerValue];

        // calculate new pad key
        padKey = [Crypto hmac:hashedProof key:challenge nbits:hashedProof.length];
        
        // append to intermediate pad
        if (i == 0) {
            [rootPad appendData:[Crypto xorData:padKey withData:rootKey]];
        } else {
            [rootPad appendData:[Crypto hmac:(i > 0 ? [Crypto sha256:rootPad] : [Crypto sha256:challenge])
                                         key:hashedProof
                                       nbits:blockSize*8]];
        }
    }
    
    // hash the intermediate pad as a commitment to the derivation work
    NSData *zipKey = [Crypto sha256:[Crypto sha256:rootPad]];
    NSMutableData *zip = [[NSMutableData alloc] init];
    
    for (NSInteger i = 0; i < blocks; i++) {
        Ky = [Crypto xorData:Ky withData:zipKey];
        zipKey = [Crypto hmac:zipKey key:Ky nbits:Ky.length*8];
        [zip appendData:[Crypto xorData:zipKey withData:[rootPad subdataWithRange:NSMakeRange(i * blockSize, blockSize)]]];
    }
    
    NSData *outputData = [Crypto xorData:zip withData:plaintext];

    if (!encrypt) {
        return outputData;
    }
    
    // create protocol blob
    NSData *protocol = [Protocol createOTPProtocolData:outputData
                                                  salt:salt
                                                rounds:rounds
                                               kdfmode:otpMode
                                            difficulty:diff];
    
    return protocol;
}


@end
