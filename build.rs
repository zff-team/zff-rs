fn main() {
    #[cfg(feature = "autodetect-cpu-instructions")]
    check_cpu_instructions();
    #[cfg(feature = "force-cpu-instructions")]
    set_all_instructions();
}

#[cfg(feature = "autodetect-cpu-instructions")]
fn check_cpu_instructions() {
    #[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
    check_x86_64_instructions();
    #[cfg(target_arch = "aarch64")]
    check_aarch64_instructions();
}

#[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
#[cfg(feature = "autodetect-cpu-instructions")]
fn check_x86_64_instructions() {
    if is_x86_feature_detected!("aes") {
        set_aes();
    }
    if is_x86_feature_detected!("sse2") {
        set_sse2();
    }
    if is_x86_feature_detected!("ssse3") {
        set_ssse3();
    }
    if is_x86_feature_detected!("sse4.1") {
        set_sse4_1();
    }
}

#[cfg(target_arch = "aaarch64")]
#[cfg(feature = "autodetect-cpu-instructions")]
fn check_aarch64_instructions() {
    if is_aarch64_feature_detected!("aes") {
        set_aes();
    }
    if is_aarch64_feature_detected!("sha2") {
        set_sha2();
    }
    if is_aarch64_feature_detected!("neon") {
        set_neon();
    }
}


#[cfg(feature = "force-cpu-instructions")]
fn set_all_instructions() {
    #[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
    force_set_x86_64_instructions();
    #[cfg(target_arch = "aarch64")]
    force_set_aarch64_instructions();
}

#[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
#[cfg(feature = "force-cpu-instructions")]
fn force_set_x86_64_instructions() {
    set_aes();
    set_sse2();
    set_ssse3();
    set_sse4_1();
}

#[cfg(target_arch = "aarch64")]
#[cfg(feature = "force-cpu-instructions")]
fn force_set_aarch64_instructions() {
    set_aes();
    set_sha2();
    set_neon();
}


#[cfg(any(target_arch = "x86",  target_arch = "x86_64", target_arch = "aarch64"))]
fn set_aes() {
    println!("cargo:rustc-cfg=has_aes");
}

#[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
fn set_sse2() {
    println!("cargo:rustc-cfg=has_sse2");
}

#[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
fn set_ssse3() {
    println!("cargo:rustc-cfg=has_ssse3");
}

#[cfg(any(target_arch = "x86",  target_arch = "x86_64"))]
fn set_sse4_1() {
    println!("cargo:rustc-cfg=has_sse4_1");
}

#[cfg(target_arch = "aarch64")]
fn set_sha2() {
    println!("cargo:rustc-cfg=has_sha2");
}

#[cfg(target_arch = "aarch64")]
fn set_neon() {
    println!("cargo:rustc-cfg=has_neon");
}