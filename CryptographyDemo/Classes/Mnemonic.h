#import <Foundation/Foundation.h>
#import "Crypto.h"

@interface Mnemonic : NSObject

// generate mnemonic from entropy
+ (NSString *)generateMemnonic:(NSData *)entropy;

// generate mnemonic with N words (12, 18, 24)
+ (NSString *)randomMemnonic:(NSInteger)Nwords;

// convert mnemonic phrase to its corresponding byte entropy
+ (NSData *)entropyFromMemnonic:(NSString *)mnemonic;

// read seed_dictionary.txt and return data
+ (NSArray *)getBIP32Dictionary;

+ (NSInteger)entropySize:(NSInteger)words;
+ (NSInteger)wordSize:(NSInteger)data;

@end
