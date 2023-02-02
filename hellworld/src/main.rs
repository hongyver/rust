fn main() {
    println!("Hello, world! {}", add(10,10));
}

fn add(x:u64, y:u64) -> u64 {
    x + y
}

#[test]
fn test_add() {
    assert_eq!(add(10,10), 20);
}