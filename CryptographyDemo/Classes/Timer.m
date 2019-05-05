#import "Timer.h"

@implementation Timer

+ (double)computeTimeInterval:(NSDate *)startTime{
    
    NSTimeInterval interval_start = [startTime timeIntervalSinceReferenceDate];
    NSTimeInterval interval = interval_start - [[NSDate date] timeIntervalSinceReferenceDate];
    
    return interval;
}

@end
