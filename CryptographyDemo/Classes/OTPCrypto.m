#import "OTPCrypto.h"
#import "Crypto.h"
#import "Timer.h"
#import "Mnemonic.h"

@implementation OTPCrypto


#pragma mark - DETERMINISTIC ONE TIME PAD ENCRYPTION - DIFFICULTY BASED
/**
 This is a deterministic OTP implementation.  It does not have the same security of a true OTP.
 
 * This function uses a password derived key (PBKDF2), split key hashing, and proof of work to generate high entropy
 data to build one time pad stream of data for encryption and decryption.

 * This implementation builds an intermediate pad through a recursive hash mechanism somewhat similar to a merkle tree using a derived key from a seed, 
 where the next hash is appended as the output based on the previous blocks (rows) in the pad. After the intermediate pad is built, we take the hash 
 of the entire pad and XOR this hash while also mutating it across the transposition of the intermediate pad.  This gives a strong security 
 property in that it can't be parallelized (it takes computational power and is memory-hard from recursive hashing of proofs).  This final step ultimately
 forces an attacker to compute the entire pad through the algorithm, otherwise we can enforce plausible deniablilty.
 
 * This implementation can also be used and tweaked in other ways, and may have other interesting properties.  

Interesting work:

1. https://arxiv.org/pdf/1906.10817
2. https://eprint.iacr.org/2019/1139
3. https://blog.ricmoo.com/sqrl-ing-mnemonic-phrases-b68b2dc1f75b

 @param seed secret input (one time password)
 @param salt public salt entropy for kdf
 @param plaintext data to encrypt
 @param rounds number of kdf iterations to derive key
 @param diff difficulty measured in number of hex characters with leading zeros
 @param encrypt flag for encrypting vs. decrypting
 @return pad data (encrypted otp data or decrypted plaintext)
 */
+ (NSData *)deriveOTP:(NSString *)seed
                 salt:(NSData *)salt
                 data:(NSData *)plaintext
               rounds:(NSInteger)rounds
           difficulty:(NSInteger)diff
              encrypt:(BOOL)encrypt{
        
    NSDate *methodStart = [NSDate date];
    
    // TODO: dynamically change block size
    BBKDFMode otpMode = otp512;
    
    // derive an initial symmetric key
    NSData *derivedKey = [Crypto deriveKey:seed
                                      salt:salt
                                      mode:otpMode
                                    rounds:rounds];
    
    double totalExecutionTime = -[Timer computeTimeInterval:methodStart];
    
    // calculate number of blocks for the pad
    NSInteger blockSize = derivedKey.length/2;
    NSInteger dataLength = plaintext.length;
    NSInteger blocks = 1;
    
    if (dataLength > blockSize) {
        blocks = floor(dataLength / blockSize) + (dataLength % blockSize == 0 ? 0 : 1);
    }
    
    // split derived key
    NSData *Kx = [derivedKey subdataWithRange:NSMakeRange(0, blockSize)];
    NSData *Ky = [derivedKey subdataWithRange:NSMakeRange(blockSize, blockSize)];
    
    // root key
    NSData *rootKey = [Crypto hmac:Kx key:Ky nbits:blockSize*8];
    
    if (diff == 0) {
        diff = 1;
    }
    
    // intermediate pad generation
    NSMutableData *ipad = [[NSMutableData alloc] init];
    NSInteger nonceTotal = 0;
    
    for (NSInteger i = 0; i < blocks; i++)
    {
        // do work
        NSDictionary *dict = [Crypto proofOfWork:rootKey difficulty:diff];
//        NSLog(@"\nproof dict: %@",dict);
        NSData *proof = [dict objectForKey:@"proof"];
        totalExecutionTime += [[dict objectForKey:@"time"] doubleValue];
        nonceTotal += [[dict objectForKey:@"nonce"] integerValue];

        // new root key
        rootKey = [Crypto hmac:proof key:rootKey nbits:blockSize*8];
        
        // add to intermediate pad
        if (i == 0) {
            [ipad appendData:proof];
        } else {
            [ipad appendData:[Crypto hmac:[Crypto sha256:ipad]
                                      key:proof
                                    nbits:blockSize*8]];
        }
    }

    // hash intermediate pad as a commitment to the derivation work
    NSData *padKey = [Crypto sha256:[Crypto sha256:ipad]];
    
    // generate final one time pad
    NSMutableData *pad = [[NSMutableData alloc] init];
    for (NSInteger i = 0; i < blocks; i++)
    {
        Kx = [Crypto xorData:Kx withData:padKey];
        padKey = [Crypto hmac:padKey key:Kx nbits:blockSize*8];
        [pad appendData:[Crypto xorData:padKey withData:[ipad subdataWithRange:NSMakeRange(i * blockSize, blockSize)]]];
    }

    // xor encryption of pad and plaintext/ciphertext
    NSData *outputData = [Crypto xorData:pad withData:plaintext];

    if (!encrypt) {
        return outputData;
    }
    
    // create protocol blob
    NSData *protocol = [Protocol createOTPProtocolData:outputData
                                                  salt:salt
                                                rounds:rounds
                                           blockRounds:0
                                               kdfmode:otpMode
                                               encmode:BBEncryptOTP_POW
                                            difficulty:diff];
    
    return protocol;
}


#pragma mark - DETERMINISTIC ONE TIME PAD ENCRYPTION - TIME BASED
/**
 Time-based deterministic one time pad using KDF
 
 * time is used to calculate number of rounds needed for KDF using CCCalibratePBKDF
 
 @param seed secret input (one time password)
 @param salt high entropy data for KDF
 @param plaintext data to encrypt
 @param padTime time in milliseconds to generate the pad
 @param rounds number of rounds for KDF
 @return pad data (encrypted pad or decrypted result)
 */
+ (NSData *)deriveTimedOTP:(NSString *)seed
                      salt:(NSData *)salt
                      data:(NSData *)plaintext
                   padTime:(double)padTime
                    rounds:(NSInteger)rounds
               blockRounds:(NSInteger)rblocks
                   encrypt:(BOOL)encrypt{
    
    NSDate *methodStart = [NSDate date];
    double totalExecutionTime = 0.0;
    double executionTime = 0.0;
    
    NSInteger nonceTotal = 0;
    NSInteger dataLength = plaintext.length;
    BBKDFMode padMode = otp512;
    
    // derive root key
    NSData *derivedKey = [Crypto deriveKey:seed
                                      salt:salt
                                      mode:padMode
                                    rounds:kPBKDFRoundsDefault];
    
    totalExecutionTime += -[Timer computeTimeInterval:methodStart];
    
    if (derivedKey == nil) {
        return nil;
    }
    
    // calculate number of blocks for the pad
    NSInteger blockSize = derivedKey.length/2;
    NSInteger nbits = blockSize*8;
    NSInteger blocks = 1;
    
    if (dataLength > blockSize) {
        blocks = floor(dataLength / blockSize) + (dataLength % blockSize == 0 ? 0 : 1);
    }
    
    BOOL continueRounds = (rblocks > 0 && rblocks > blocks);
    
    // calculate pad block time
    double timePerBlock = padTime/blocks;
    if (timePerBlock < kMSEC_IN_SEC) {
        timePerBlock = kMSEC_IN_SEC;
    }
    
    // need to know number of rounds to decrypt
    if (encrypt && rounds == 0) {
        rounds = [Crypto KDFRoundsForDerivationTime:timePerBlock
                                     passwordLength:(size_t)seed.length
                                         saltLength:salt.length
                                        ccAlgorithm:kCCPRFHmacAlgSHA512
                                   derivedKeyLength:salt.length];
    }

    nonceTotal += rounds;
    NSInteger blockRounds = rounds;

    // split key
    NSData *Kx = [Crypto sha256:[derivedKey subdataWithRange:NSMakeRange(0, blockSize)]];
    NSData *Ky = [Crypto sha256:[derivedKey subdataWithRange:NSMakeRange(blockSize, blockSize)]];
    NSData *mutableSalt = [Crypto hmac:Kx key:Ky nbits:nbits];

    // build intermediate pad
    NSMutableData *ipad = [[NSMutableData alloc] init];

    NSInteger tempBlocks = blocks;
    for (NSInteger i = 0; i < tempBlocks; i++)
    {
        methodStart = [NSDate date];
        
        // derive new key for block
        derivedKey = [Crypto deriveKey:[Mnemonic generateMemnonic:Kx]
                                  salt:mutableSalt
                                  mode:padMode
                                rounds:blockRounds++];
        // split keys
        Kx = [derivedKey subdataWithRange:NSMakeRange(0, blockSize)];
        Ky = [derivedKey subdataWithRange:NSMakeRange(blockSize, blockSize)];
        // mutate salt
        mutableSalt = [Crypto xorData:[Crypto sha256:Kx] withData:[Crypto sha256:Ky]];

        // make sure we take atleast padTime to execute
        if (encrypt) {
            double tempExecutionTime = -[Timer computeTimeInterval:methodStart];
            if (totalExecutionTime + tempExecutionTime < padTime/1000.0) {
                totalExecutionTime += tempExecutionTime;
                nonceTotal += blockRounds;
                tempBlocks++;
                continue;
            }
        } else if (continueRounds) {
            if (tempBlocks < rblocks) {
                tempBlocks++;
            }
            continueRounds = (tempBlocks < rblocks);
            nonceTotal += blockRounds;
            continue;
        }
        
        // append hmac of split keys
        [ipad appendData:[Crypto hmac:(i == 0 ? Kx : [Crypto sha256:ipad])
                                  key:Ky
                                nbits:nbits]];
        
        executionTime = -[Timer computeTimeInterval:methodStart];
        totalExecutionTime += executionTime;
        nonceTotal += blockRounds;
    }
    
    // hash intermediate pad as a commitment to the derivation work
    NSData *ikey = [Crypto sha256:[Crypto sha256:ipad]];
    
    // generate final one time pad using commitment
    NSMutableData *pad = [[NSMutableData alloc] init];
    for (NSInteger i = 0; i < blocks; i++)
    {
        NSMutableData *tempHash = [[NSMutableData alloc] initWithData:ikey];
        [tempHash appendData:[DataFormatter hexStringToData:[DataFormatter hexFromInt:(nonceTotal-i) prefix:NO]]];
        ikey = [Crypto sha256:tempHash];
        [pad appendData:[Crypto xorData:ikey withData:[ipad subdataWithRange:NSMakeRange(i * blockSize, blockSize)]]];
    }
    
    // xor encryption of pad and plaintext/ciphertext
    NSData *outputData = [Crypto xorData:pad withData:plaintext];
    
    if (!encrypt) {
        return outputData;
    }

    // create protocol blob
    NSData *protocol = [Protocol createOTPProtocolData:outputData
                                                  salt:salt
                                                rounds:rounds
                                           blockRounds:tempBlocks
                                               kdfmode:masterKey
                                               encmode:BBEncryptOTP_TIME
                                            difficulty:0];

    return protocol;
}


@end
