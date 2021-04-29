sym_finder: the library for symbol lookup (for my study)
----

```rust
let pid = process::id() as pid_t;
let sym = sym_finder::find_sym(pid, "libc", "gethostbyname");
println!("the offset of gethostbyname is {}", sym.st_value);
# => the offset of gethostbyname is 0xcafebabe
```
