// Experimental: a list derived from an inventory of weak links, not Apple's own policy.
// Absent-cache/absent-disk edges usually exit before this check.
static const std::unordered_set<std::string_view> allowedMissingWeakDylibs = {
    "/AppleInternal/Library/Frameworks/CalDAVServerSimulator.framework/Versions/A/CalDAVServerSimulator",
    "/AppleInternal/Library/Frameworks/VisualLogger.framework/Versions/A/VisualLogger",
    "/System/Library/Frameworks/ExposureNotification.framework/Versions/A/ExposureNotification",
    "/System/Library/Frameworks/SecureConfigDB.framework/Versions/A/SecureConfigDB",
    "/System/Library/PrivateFrameworks/IntelligencePlatformLibrary_AppleInternal.framework/Versions/A/IntelligencePlatformLibrary_AppleInternal",
    "/System/Library/PrivateFrameworks/MLCompilerRuntime.framework/Versions/A/Libraries/libmlc_rt.dylib",
    "/System/Library/PrivateFrameworks/RemoteProcessingBlock.framework/Versions/A/RemoteProcessingBlock",
    "/System/Library/PrivateFrameworks/libnarrativecert.framework/Versions/A/libnarrativecert",
    "/usr/lib/libobjc-env.dylib",
};
