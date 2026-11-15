#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <stdio.h>

extern uint32_t dyld_get_active_platform(void);

int main(void) { @autoreleasepool {
    const char *path = "/System/Library/Frameworks/UIKit.framework/UIKit";
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "UIKit load: %s\n", dlerror()); return 1; }
    Class responder = NSClassFromString(@"UIResponder");
    Class color = NSClassFromString(@"UIColor");
    if (!responder || !color) { fputs("UIKit classes missing\n", stderr); return 2; }
    id value = ((id (*)(id, SEL, double, double, double, double))objc_msgSend)(
        color, sel_registerName("colorWithRed:green:blue:alpha:"), 0.25, 0.5, 0.75, 1.0);
    double red = 0, green = 0, blue = 0, alpha = 0;
    BOOL ok = ((BOOL (*)(id, SEL, double *, double *, double *, double *))objc_msgSend)(
        value, sel_registerName("getRed:green:blue:alpha:"), &red, &green, &blue, &alpha);
    printf("platform=%u responder=%s color=%d %.2f %.2f %.2f %.2f\n",
           dyld_get_active_platform(), class_getName(responder), (int)ok, red, green, blue, alpha);
    return ok && red == 0.25 && green == 0.5 && blue == 0.75 && alpha == 1.0 ? 0 : 3;
} }
