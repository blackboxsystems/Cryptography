#import "DataFormatter.h"

@implementation DataFormatter


+ (NSString *)hexDataToString:(NSData *)hexData {
    
    NSString *hex = [NSString stringWithFormat:@"%@",hexData];
    hex = [[[hex stringByReplacingOccurrencesOfString:@" " withString:@""] stringByReplacingOccurrencesOfString:@"<" withString:@""] stringByReplacingOccurrencesOfString:@">" withString:@""];
    
    return hex.lowercaseString;
}
+ (NSData * _Nullable)hexStringToData:(NSString *)str {
    
    if (str.length < 2) {
        return nil;
    }
    
    if ([[str substringToIndex:2] isEqualToString:@"0x"]) {
        str = [str substringFromIndex:2];
    }
    
    str = [str stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSMutableData *commandToSend = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    
    for (int i = 0; i < [str length]/2; i++) {
        byte_chars[0] = [str characterAtIndex:i*2];
        byte_chars[1] = [str characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [commandToSend appendBytes:&whole_byte length:1];
    }
    
    return commandToSend;
}

+ (NSString *)hexToBinary:(NSString*)hexString {
    
    NSMutableString *retnString = [NSMutableString string];
    
    for (int i = 0; i < [hexString length]; i++) {
        char c = [[hexString lowercaseString] characterAtIndex:i];
        switch (c) {
            case '0': [retnString appendString:@"0000"]; break;
            case '1': [retnString appendString:@"0001"]; break;
            case '2': [retnString appendString:@"0010"]; break;
            case '3': [retnString appendString:@"0011"]; break;
            case '4': [retnString appendString:@"0100"]; break;
            case '5': [retnString appendString:@"0101"]; break;
            case '6': [retnString appendString:@"0110"]; break;
            case '7': [retnString appendString:@"0111"]; break;
            case '8': [retnString appendString:@"1000"]; break;
            case '9': [retnString appendString:@"1001"]; break;
            case 'a': [retnString appendString:@"1010"]; break;
            case 'b': [retnString appendString:@"1011"]; break;
            case 'c': [retnString appendString:@"1100"]; break;
            case 'd': [retnString appendString:@"1101"]; break;
            case 'e': [retnString appendString:@"1110"]; break;
            case 'f': [retnString appendString:@"1111"]; break;
            default : break;
        }
    }
    
    return retnString;
}
+ (int)binaryStringToInt:(NSString *) binaryString {
    
    unichar aChar;
    int value = 0;
    int index;
    
    for (index = 0; index < [binaryString length]; index++) {
        aChar = [binaryString characterAtIndex:index];
        if (aChar == '1') {
            value += 1;
        }
        if (index + 1 < [binaryString length]) {
            value = value << 1;
        }
    }
    
    return value;
}

+ (NSString *)hexFromInt:(NSInteger)val prefix:(BOOL)prefix{
    
    NSString *rtn = [NSString stringWithFormat:@"%X", (unsigned int)val];
    
    if (rtn.length % 2 != 0 || rtn.length < 2) {
        rtn = [NSString stringWithFormat:@"0%@", rtn];
    }
    
    return [NSString stringWithFormat:@"%@%@", (prefix ? @"0x":@""), rtn.lowercaseString];
}
+ (int)hexDataToInt:(NSData *)hex{
    return [self binaryStringToInt:[self hexToBinary:[self hexDataToString:hex]]];
}

+ (NSString *)binaryToHex:(NSString *)binaryString{
    
    NSMutableString *str = [[NSMutableString alloc] init];
    NSInteger nbits = binaryString.length;
    
    NSInteger nbuckets = floor(nbits/4);
    
    for (NSInteger i = 0; i < nbuckets; i++) {
        NSString *b = [[binaryString lowercaseString] substringWithRange:NSMakeRange(i*4, 4)];
        NSString *hex;
        if ([b isEqualToString:@"0000"]) {
            hex = @"0";
        } else if ([b isEqualToString:@"0001"]) {
            hex = @"1";
        } else if ([b isEqualToString:@"0010"]) {
            hex = @"2";
        } else if ([b isEqualToString:@"0011"]) {
            hex = @"3";
        } else if ([b isEqualToString:@"0100"]) {
            hex = @"4";
        } else if ([b isEqualToString:@"0101"]) {
            hex = @"5";
        } else if ([b isEqualToString:@"0110"]) {
            hex = @"6";
        } else if ([b isEqualToString:@"0111"]) {
            hex = @"7";
        } else if ([b isEqualToString:@"1000"]) {
            hex = @"8";
        } else if ([b isEqualToString:@"1001"]) {
            hex = @"9";
        } else if ([b isEqualToString:@"1010"]) {
            hex = @"a";
        } else if ([b isEqualToString:@"1011"]) {
            hex = @"b";
        } else if ([b isEqualToString:@"1100"]) {
            hex = @"c";
        } else if ([b isEqualToString:@"1101"]) {
            hex = @"d";
        } else if ([b isEqualToString:@"1110"]) {
            hex = @"e";
        } else if ([b isEqualToString:@"1111"]) {
            hex = @"f";
        } else {
            hex = @"0";
        }
        [str appendString:hex];
    }
    
    return str;
}

@end
