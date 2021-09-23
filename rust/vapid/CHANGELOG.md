# 0.4.0

* Changed `VapidErrors` to be more Clippy friendly
* updates for latest rust


# 0.2.0

Due to changes in the OpenSSL library, several calls changed form from `0.1.0`

Most calls now return as a `Result<_, VapidError>`. `VapidError` is a type of `failure` call, so it should make logging and error handling a bit easier.

This does mean that

```rust, no_run
let key = Key::generate();
```
is now
```rust, no_run
let key = Key.generate().unwrap();
```

The `.group()` method for `Key` has been removed. It was a convenience function. You can replace it with generating the group directly
`ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)?`

There are now `VapidErrors`