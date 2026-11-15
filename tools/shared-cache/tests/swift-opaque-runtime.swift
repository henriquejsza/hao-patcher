public protocol P {}
private struct Box<T>: P { var value: T }
public func make<T: Hashable>(_ value: T) -> some P { Box(value: value) }
@_cdecl("fixture_metadata") public func fixtureMetadata() -> UnsafeRawPointer {
    unsafeBitCast(type(of: make(UInt(1))), to: UnsafeRawPointer.self)
}
