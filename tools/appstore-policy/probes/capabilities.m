#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc < 2) {
        fputs("usage: capabilities CAPABILITY [CAPABILITY ...]\n", stderr);
        return 2;
    }
    void *handle = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW | RTLD_LOCAL);
    CFTypeRef (*copyAnswer)(CFStringRef, CFDictionaryRef) =
        handle ? dlsym(handle, "MGCopyAnswer") : NULL;
    if (!copyAnswer) {
        fputs("MobileGestalt unavailable\n", stderr);
        return 3;
    }
    NSMutableArray *rows = [NSMutableArray array];
    for (int i = 1; i < argc; ++i) {
        NSString *name = [NSString stringWithUTF8String:argv[i]];
        if (!name) return 2;
        CFTypeRef answer = copyAnswer((__bridge CFStringRef)name, NULL);

        [rows addObject:@{
            @"capability": name,
            @"present": @(answer != NULL),
            @"boolean": @(answer && CFGetTypeID(answer) == CFBooleanGetTypeID()),
            @"acceptedByStoreCapabilityCheck": @(answer == kCFBooleanTrue)
        }];
        if (answer) CFRelease(answer);
    }
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:rows
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    if (!json) return 4;
    fwrite(json.bytes, 1, json.length, stdout);
    fputc('\n', stdout);
    return 0;
} }
