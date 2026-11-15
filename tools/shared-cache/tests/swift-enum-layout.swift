import Combine

@_silgen_name("exercise_enum_layout")
func exerciseEnumLayout(_ value: UnsafeRawPointer, _ metadata: UnsafeRawPointer) -> Int32

func exercise<T>(_ value: T) -> Int {
    withUnsafePointer(to: value) {
        Int(exerciseEnumLayout(UnsafeRawPointer($0), unsafeBitCast(T.self, to: UnsafeRawPointer.self)))
    }
}

func children(_ value: Any, depth: Int = 0) -> Int {
    let count = _openExistential(value, do: exercise)
    if count > 0 || depth == 3 { return count }
    return Mirror(reflecting: value).children.reduce(0) { $0 + children($1.value, depth: depth + 1) }
}

// Combine's actual generic Storage enum uses the target runtime's layout strings.
// Exercise both its inline-value and publisher-object cases, keeping live owners.
var published = Published(initialValue: String(repeating: "layout", count: 20))
let inline = children(published)
let publisher = published.projectedValue
let boxed = children(published)
precondition(inline > 0 && boxed > 0, "Both native enum branches must be exercised")
withExtendedLifetime(publisher) { print("PASS both Published.Storage cases:", inline, boxed) }
