#import <Foundation/Foundation.h>

#ifdef WRONG_GATE_ABI
typedef NSInteger GateFlag;
#else
typedef BOOL GateFlag;
#endif

@interface Device : NSObject
- (BOOL)isAppleSiliconMac;
@end
@implementation Device
- (BOOL)isAppleSiliconMac { return NO; }
@end

@interface PurchaseInfo : NSObject
@property NSInteger expectedSoftwarePlatform;
#ifdef WRONG_ABI
@property NSInteger requireUniversal;
#else
@property BOOL requireUniversal;
#endif
@end
@implementation PurchaseInfo
@end

@interface ASKMobileGestalt : NSObject
+ (BOOL)isAppleSiliconMac;
+ (BOOL)hasCapabilitiesIncludingCompatibilityCheck:(id)capabilities isVisionOSCompatibleIOSApp:(GateFlag)vision;
@end
static BOOL loadSawCapability;
static unsigned gateCalls;
@implementation ASKMobileGestalt
+ (BOOL)isAppleSiliconMac { return NO; }
+ (BOOL)hasCapabilitiesIncludingCompatibilityCheck:(id)capabilities isVisionOSCompatibleIOSApp:(GateFlag)vision {
    gateCalls++;
    return vision || [capabilities isEqual:@[@"arm64"]];
}
+ (void)load { loadSawCapability = [self isAppleSiliconMac]; }
@end
BOOL fixture_load_saw_capability(void) { return loadSawCapability; }
unsigned fixture_gate_calls(void) { return gateCalls; }
