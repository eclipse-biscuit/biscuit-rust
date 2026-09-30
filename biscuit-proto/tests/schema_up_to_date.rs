use std::io::Read;

#[test]
fn schema_up_to_date() {
    let out_dir = match std::env::var("OUT_DIR") {
        Ok(dir) => dir,
        Err(_) => return,
    };
    prost_build::compile_protos(&["src/schema.proto"], &["src/"]).unwrap();
    let mut generated = String::new();
    std::fs::File::open(format!("{out_dir}/biscuit.format.schema.rs"))
        .unwrap()
        .read_to_string(&mut generated)
        .unwrap();

    let committed = include_str!("../src/lib.rs");

    if generated != committed {
        println!(
            "{}",
            colored_diff::PrettyDifference {
                expected: &generated,
                actual: committed,
            }
        );
        panic!("biscuit-proto/src/lib.rs is out of date with biscuit-proto/src/schema.proto");
    }
}
