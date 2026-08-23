use std::collections::HashMap;

use auscan_lib::error::AppError;
use auscan_lib::scope::{self, Scope, ScopeKind};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    scopes: HashMap<String, SpecJson>,
    cases: Vec<CaseJson>,
    entries: Vec<EntryJson>,
}

#[derive(Deserialize)]
struct SpecJson {
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Deserialize)]
struct CaseJson {
    scope: String,
    target: String,
    expect: String,
}

#[derive(Deserialize)]
struct EntryJson {
    input: String,
    expect: String,
}

const CORPUS: &str = include_str!("../../fixtures/scope/corpus.json");

fn construir(spec: &SpecJson) -> Scope {
    let mut e: Vec<(ScopeKind, String)> = Vec::new();
    for a in &spec.allow {
        e.push((ScopeKind::Allow, a.clone()));
    }
    for d in &spec.deny {
        e.push((ScopeKind::Deny, d.clone()));
    }
    Scope::from_entries(&e).expect("el corpus solo trae entradas válidas")
}

fn veredicto(s: &Scope, target: &str) -> &'static str {
    match s.validate(target) {
        Ok(_) => "in",
        Err(AppError::OutOfScope(_)) => "out",
        Err(AppError::EmptyScope) => "empty-scope",
        Err(AppError::InvalidAddress(_)) => "invalid",
        Err(otro) => panic!("veredicto inesperado: {otro:?}"),
    }
}

#[test]
fn el_guard_coincide_con_el_corpus() {
    let c: Corpus = serde_json::from_str(CORPUS).expect("corpus mal formado");
    for caso in &c.cases {
        let spec = c.scopes.get(&caso.scope).expect("scope inexistente en el corpus");
        let s = construir(spec);
        assert_eq!(
            veredicto(&s, &caso.target),
            caso.expect,
            "scope {} · objetivo {:?}",
            caso.scope,
            caso.target
        );
    }
}

#[test]
fn el_parser_de_entradas_coincide_con_el_corpus() {
    let c: Corpus = serde_json::from_str(CORPUS).expect("corpus mal formado");
    for e in &c.entries {
        let real = match scope::parse_entry(&e.input) {
            Ok(_) => "ok",
            Err(AppError::AmbiguousCidr(_)) => "ambiguous",
            Err(AppError::OverbroadScope(_)) => "overbroad",
            Err(AppError::InvalidAddress(_)) => "invalid",
            Err(otro) => panic!("veredicto inesperado: {otro:?}"),
        };
        assert_eq!(real, e.expect, "entrada {:?}", e.input);
    }
}
