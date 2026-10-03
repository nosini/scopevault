// The module calls into libpam. Link it by file name: building needs no
// libpam development symlink (`libpam.so`), only the library itself.
fn main() {
    println!("cargo:rustc-link-arg=-l:libpam.so.0");
}
