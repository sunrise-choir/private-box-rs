use std::process::Command;
use std::env;

fn main() {
    println!("rerun-if-env-changed=SODIUM_STATIC");
    println!("rerun-if-env-changed=SODIUM_LIB_DIR");
    println!("rerun-if-env-changed=SODIUM_INSTALL_DIR");

    match env::var("SODIUM_STATIC") {
        Ok(_) => {
            env::var("SODIUM_LIB_DIR").expect("SODIUM_LIB_DIR was not set");
            env::var("SODIUM_INSTALL_DIR").expect("SODIUM_INSTALL_DIR was not set");

            //TODO: don't want to clean every time.
            Command::new("make").args(&["clean"])
                .status() //Clean might fail if the project wasn't configured or was cleaned already. Just ignore result.
                .map(|_|())
                .map_err(|_|())
                .unwrap();

            Command::new("make").args(&["libsodium", "-j4"])
                .status()
                .expect("could not make libsodium");
        },
        _ => ()
    };
}
