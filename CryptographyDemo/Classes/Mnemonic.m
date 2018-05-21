//
//  Mnemonic.m
//  CryptographyDemo
//
//  Created by Hello World on 5/15/18.
//  Copyright © 2018 blackboxsystems. All rights reserved.
//

#import "Mnemonic.h"

@implementation Mnemonic : NSObject

NS_ENUM(NSInteger, CCSeedWords) {
    kSeedWords_12 = 12,
    kSeedWords_18 = 18,
    kSeedWords_24 = 24
};

NS_ENUM(NSInteger, CCSeedEntropy) {
    kSeedEntropy_12 = 16,
    kSeedEntropy_18 = 24,
    kSeedEntropy_24 = 32
};

/*  -------------------------------------------------------------
 //  Mnemonic Generatation
 //  ------------------------------------------------------------
 */
+ (NSString *)generateMemnonic:(NSData *)entropy {
    
    NSInteger Nwords;
    size_t nbytes = entropy.length;
    switch (nbytes) {
        case kSeedEntropy_12:
            Nwords = kSeedWords_12;
            break;
        case kSeedEntropy_18:
            Nwords = kSeedWords_18;
            break;
        case kSeedEntropy_24:
            Nwords = kSeedWords_24;
            break;
        default:
            Nwords = kSeedWords_12;
            break;
    }
    
    if (entropy == nil) {
        entropy = [Crypto generateRandomCrytoBytes:nbytes];
    } else {
        if (nbytes < entropy.length) {
            entropy = [entropy subdataWithRange:NSMakeRange(0, nbytes)];
        }
    }
    
    NSMutableData *bitmap = [[NSMutableData alloc] initWithData:entropy];
    NSData *hash = [Crypto SHA:entropy nbits:nbytes*8];
    NSData *checksum = [hash subdataWithRange:NSMakeRange(0, 2)];
    [bitmap appendData:checksum];
    
    NSString *bitmapString = [DataFormatter hexDataToString:bitmap];
    NSString *hex = [bitmapString substringToIndex:bitmapString.length-1];
    NSString *binary = [DataFormatter hexToBinary:hex];
    
    NSMutableArray *mapping = [[NSMutableArray alloc] initWithCapacity:Nwords];
    NSUInteger Nbits = binary.length/Nwords;
    for (NSInteger i = 0; i < Nwords; i++) {
        [mapping addObject:[binary substringToIndex:Nbits]];
        binary = [binary substringFromIndex:Nbits];
    }
    
    NSMutableArray *indexes = [[NSMutableArray alloc] init];
    for (NSInteger i = 0; i < Nwords; i++) {
        [indexes addObject:[NSString stringWithFormat:@"%i",[DataFormatter binaryStringToInt:mapping[i]]]];
    }
    
    NSArray *dictionary = [self getDictionary];
    NSMutableString *phrase = [[NSMutableString alloc] init];
    
    for (NSInteger i = 0; i < Nwords; i++) {
        NSString *word = [dictionary objectAtIndex:[[indexes objectAtIndex:i] integerValue]];
        [phrase appendString:[NSString stringWithFormat:@"%@ ",word]];
    }
    
    NSString *mnemonic = [[phrase stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]
                          stringByReplacingOccurrencesOfString:@"-" withString:@" "];
    
    return mnemonic;
}

+ (NSString *)randomMemnonic:(NSInteger)Nwords {
    
    size_t nbytes;
    
    switch (Nwords) {
        case kSeedWords_12:
            nbytes = kSeedEntropy_12;
            break;
        case kSeedWords_18:
            nbytes = kSeedEntropy_18;
            break;
        case kSeedWords_24:
            nbytes = kSeedEntropy_24;
            break;
        default:
            nbytes = kSeedEntropy_12;
            break;
    }
    
    NSString *mnemonic = [self generateMemnonic:[[Crypto generateRandomCrytoBytes:nbytes] subdataWithRange:NSMakeRange(0, nbytes)]];
    
    return mnemonic;
}


+ (NSArray *)getDictionary {
    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"seed_dictionary" ofType:@"txt"];
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    // integrity check on file
    assert([[DataFormatter hexDataToString:[Crypto SHA:data nbits:256]] isEqualToString:@"c1be978261f9acab4ab29806c57de07c7bea0a06acbc94f227d248da9b290c6b"]);
    NSString *dicts = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    return [dicts componentsSeparatedByString:@"-"];
}


@end
