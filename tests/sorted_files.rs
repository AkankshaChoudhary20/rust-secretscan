use secretscan::scanner::walk_files;
#[test]
fn directory_walk_is_sorted_by_relative_path() {
 let root=std::env::temp_dir().join(format!("secretscan-sort-{}",std::process::id()));
 std::fs::create_dir_all(root.join("nested")).unwrap();
 for name in ["z.env","nested/b.env","a.env"] {std::fs::write(root.join(name),"test").unwrap();}
 let files=walk_files(&root).unwrap();
 let relative:Vec<_>=files.iter().map(|p|p.strip_prefix(&root).unwrap().to_str().unwrap()).collect();
 assert_eq!(relative,vec!["a.env","nested/b.env","z.env"]);
 std::fs::remove_dir_all(root).unwrap();
}
