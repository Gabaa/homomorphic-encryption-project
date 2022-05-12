pub fn params_1024degree() -> Parameters {
    let q = Integer::from_str("6440092097492369874468694478456476902429935263779065830479393474203066496323859298183983608879").unwrap();
    let p = Integer::from_str("127").unwrap();
    Parameters::new(q, 3.2, 3.2, 1024, p)
}
