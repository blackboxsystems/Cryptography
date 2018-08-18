#import <Foundation/Foundation.h>

@interface DataFormatter : NSObject

+ (NSString *)hexDataToString:(NSData *)hexd;

// Hex String to Data
+ (NSData *)hexStringToData:(NSString *)str;

// Hex/Binary/Int
+ (NSString*)hexToBinary:(NSString*)hexString;
+ (NSString *)hexFromInt:(NSInteger)val;
+ (int)hexDataToInt:(NSData *)hex;

// Binary String to Integer
+ (int)binaryStringToInt:(NSString *) binaryString;


@end
