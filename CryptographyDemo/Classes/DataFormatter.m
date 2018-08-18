#import "DataFormatter.h"

@implementation DataFormatter


+ (NSString *)hexDataToString:(NSData *)hexData {
    
    NSString *hex = [[[[NSString stringWithFormat:@"%@",hexData]
                       stringByReplacingOccurrencesOfString:@" " withString:@""]
                      stringByReplacingOccurrencesOfString:@"<" withString:@""]
                     stringByReplacingOccurrencesOfString:@">" withString:@""];
    return hex;
}

+ (NSData *)hexStringToData:(NSString *)str {
    
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

+ (NSString*)hexToBinary:(NSString*)hexString {
    
    NSMutableString *str = [NSMutableString string];
    
    for (int i = 0; i < [hexString length]; i++) {
        char c = [[hexString lowercaseString] characterAtIndex:i];
        switch (c) {
            case '0': [str appendString:@"0000"]; break;
            case '1': [str appendString:@"0001"]; break;
            case '2': [str appendString:@"0010"]; break;
            case '3': [str appendString:@"0011"]; break;
            case '4': [str appendString:@"0100"]; break;
            case '5': [str appendString:@"0101"]; break;
            case '6': [str appendString:@"0110"]; break;
            case '7': [str appendString:@"0111"]; break;
            case '8': [str appendString:@"1000"]; break;
            case '9': [str appendString:@"1001"]; break;
            case 'a': [str appendString:@"1010"]; break;
            case 'b': [str appendString:@"1011"]; break;
            case 'c': [str appendString:@"1100"]; break;
            case 'd': [str appendString:@"1101"]; break;
            case 'e': [str appendString:@"1110"]; break;
            case 'f': [str appendString:@"1111"]; break;
            default : break;
        }
    }
    
    return str;
}

+ (int) binaryStringToInt:(NSString *) binaryString {
    
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

+ (NSString *)hexFromInt:(NSInteger)val {
    
    NSString *str = [NSString stringWithFormat:@"%X", (unsigned int)val];
    if (str.length % 2 != 0 || str.length < 2) {
        str = [NSString stringWithFormat:@"0%@", str];
    }
    
    return [NSString stringWithFormat:@"0x%@", str];
}

+ (int)hexDataToInt:(NSData *)hex{
    return [self binaryStringToInt:[self hexToBinary:[self hexDataToString:hex]]];
}


@end
