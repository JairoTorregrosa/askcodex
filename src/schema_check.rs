//! Local re-check of a `--schema` answer against the schema it was asked for.
//!
//! The backend enforces the schema in strict mode (verified live,
//! docs/PROTOCOL.md §3.7), but that is a dated observation, not a contract:
//! an answer that parses yet breaks the schema must never reach a caller as
//! a successful `result.json`. This module checks the keywords that decide
//! the SHAPE of the answer, which is what a caller relies on when it reads
//! fields out of it:
//!
//! - `type` (one name or a list; `integer` accepts any whole number),
//! - `properties`, `required`, `additionalProperties` (`false` or a schema),
//! - `items`, `prefixItems`, `minItems`, `maxItems`,
//! - `enum`, `const` (numbers compared by value, so `1` equals `1.0`),
//! - `anyOf`, `allOf`, `oneOf`, `not`,
//! - `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`,
//!   `minLength`, `maxLength`,
//! - local `$ref` (`#`, `#/$defs/...`, any JSON pointer into the schema).
//!
//! `pattern`, `format`, `multipleOf` and the other value keywords are left to
//! the backend; docs/OUTPUT.md says so. Errors name a JSON pointer and the
//! rule, never the offending value: the answer may hold the private record
//! being extracted.

use serde_json::{Map, Value};

/// Nesting budget for schema evaluation. A `$ref` cycle that consumes no
/// input (`{"$ref": "#"}`) would otherwise recurse forever.
const MAX_DEPTH: usize = 128;

/// The first violation found: where in the answer, and which rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// JSON pointer into the answer (`""` is the whole answer).
    pub at: String,
    pub rule: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let at = if self.at.is_empty() { "/" } else { &self.at };
        write!(f, "at {at}: {}", self.rule)
    }
}

/// Check `answer` against `schema`; `Ok(())` when nothing is violated.
pub fn check(schema: &Value, answer: &Value) -> Result<(), Violation> {
    Checker { root: schema }.check(schema, answer, "", 0)
}

struct Checker<'a> {
    root: &'a Value,
}

fn fail(at: &str, rule: impl Into<String>) -> Result<(), Violation> {
    Err(Violation {
        at: at.to_string(),
        rule: rule.into(),
    })
}

fn child(at: &str, key: &str) -> String {
    format!("{at}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// JSON-Schema equality: numbers by value, everything else structurally.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => same_number(x, y),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// Integers compare exactly; anything else (a fraction, or an integer next
/// to a float such as `1` and `1.0`) compares as f64.
fn same_number(a: &serde_json::Number, b: &serde_json::Number) -> bool {
    if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (a.as_u64(), b.as_u64()) {
        return x == y;
    }
    matches!((a.as_f64(), b.as_f64()), (Some(x), Some(y)) if x == y)
}

fn is_type(value: &Value, name: &str) -> bool {
    match name {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "number" => value.is_number(),
        "integer" => match value {
            Value::Number(n) => {
                n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0)
            }
            _ => false,
        },
        // An unknown type name matches nothing, so the answer fails loudly
        // rather than passing a check that never ran.
        _ => false,
    }
}

impl Checker<'_> {
    fn resolve(&self, reference: &str, at: &str) -> Result<&Value, Violation> {
        let pointer = reference.strip_prefix('#').ok_or_else(|| Violation {
            at: at.to_string(),
            rule: format!("cannot check remote $ref {reference:?}"),
        })?;
        self.root.pointer(pointer).ok_or_else(|| Violation {
            at: at.to_string(),
            rule: format!("$ref {reference:?} points at nothing in the schema"),
        })
    }

    fn check(
        &self,
        schema: &Value,
        value: &Value,
        at: &str,
        depth: usize,
    ) -> Result<(), Violation> {
        if depth > MAX_DEPTH {
            return fail(at, "schema nesting too deep to check (a $ref cycle?)");
        }
        let schema = match schema {
            Value::Bool(true) => return Ok(()),
            Value::Bool(false) => return fail(at, "the schema allows nothing here"),
            Value::Object(schema) => schema,
            _ => return fail(at, "the schema here is not an object or boolean"),
        };
        let next = depth + 1;

        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let target = self.resolve(reference, at)?;
            self.check(target, value, at, next)?;
        }
        self.check_type(schema, value, at)?;
        self.check_choices(schema, value, at)?;
        self.check_combinators(schema, value, at, next)?;
        self.check_bounds(schema, value, at)?;
        match value {
            Value::Object(object) => self.check_object(schema, object, at, next),
            Value::Array(items) => self.check_array(schema, items, at, next),
            _ => Ok(()),
        }
    }

    fn check_type(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        at: &str,
    ) -> Result<(), Violation> {
        let names: Vec<&str> = match schema.get("type") {
            None => return Ok(()),
            Some(Value::String(name)) => vec![name.as_str()],
            Some(Value::Array(names)) => names.iter().filter_map(Value::as_str).collect(),
            Some(_) => return fail(at, "the schema's type is not a string or a list"),
        };
        if names.iter().any(|name| is_type(value, name)) {
            Ok(())
        } else {
            fail(at, format!("expected type {}", names.join(" or ")))
        }
    }

    fn check_choices(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        at: &str,
    ) -> Result<(), Violation> {
        if let Some(options) = schema.get("enum").and_then(Value::as_array)
            && !options.iter().any(|option| same(option, value))
        {
            return fail(at, "value is not one of the enum options");
        }
        if let Some(constant) = schema.get("const")
            && !same(constant, value)
        {
            return fail(at, "value differs from const");
        }
        Ok(())
    }

    fn check_combinators(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        at: &str,
        depth: usize,
    ) -> Result<(), Violation> {
        let branches = |key| schema.get(key).and_then(Value::as_array);
        if let Some(all) = branches("allOf") {
            for branch in all {
                self.check(branch, value, at, depth)?;
            }
        }
        if let Some(any) = branches("anyOf")
            && !any
                .iter()
                .any(|branch| self.check(branch, value, at, depth).is_ok())
        {
            return fail(at, "value matches none of the anyOf branches");
        }
        if let Some(one) = branches("oneOf") {
            let matched = one
                .iter()
                .filter(|branch| self.check(branch, value, at, depth).is_ok())
                .count();
            if matched != 1 {
                return fail(
                    at,
                    format!("value matches {matched} oneOf branches, not exactly 1"),
                );
            }
        }
        if let Some(not) = schema.get("not")
            && self.check(not, value, at, depth).is_ok()
        {
            return fail(at, "value matches the schema under not");
        }
        Ok(())
    }

    fn check_bounds(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        at: &str,
    ) -> Result<(), Violation> {
        let bound = |key| schema.get(key).and_then(Value::as_f64);
        if let Some(number) = value.as_f64() {
            if bound("minimum").is_some_and(|min| number < min) {
                return fail(at, "number is below minimum");
            }
            if bound("maximum").is_some_and(|max| number > max) {
                return fail(at, "number is above maximum");
            }
            if bound("exclusiveMinimum").is_some_and(|min| number <= min) {
                return fail(at, "number is not above exclusiveMinimum");
            }
            if bound("exclusiveMaximum").is_some_and(|max| number >= max) {
                return fail(at, "number is not below exclusiveMaximum");
            }
        }
        if let Some(text) = value.as_str() {
            let length = text.chars().count() as f64;
            if bound("minLength").is_some_and(|min| length < min) {
                return fail(at, "string is shorter than minLength");
            }
            if bound("maxLength").is_some_and(|max| length > max) {
                return fail(at, "string is longer than maxLength");
            }
        }
        Ok(())
    }

    fn check_object(
        &self,
        schema: &Map<String, Value>,
        object: &Map<String, Value>,
        at: &str,
        depth: usize,
    ) -> Result<(), Violation> {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    return fail(at, format!("missing required property {key:?}"));
                }
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (key, member) in object {
            let path = child(at, key);
            match properties.and_then(|p| p.get(key)) {
                Some(property) => self.check(property, member, &path, depth)?,
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => {
                        return fail(at, format!("property {key:?} is not allowed"));
                    }
                    Some(extra @ Value::Object(_)) => self.check(extra, member, &path, depth)?,
                    _ => {}
                },
            }
        }
        Ok(())
    }

    fn check_array(
        &self,
        schema: &Map<String, Value>,
        items: &[Value],
        at: &str,
        depth: usize,
    ) -> Result<(), Violation> {
        let count = items.len() as f64;
        let bound = |key| schema.get(key).and_then(Value::as_f64);
        if bound("minItems").is_some_and(|min| count < min) {
            return fail(at, "array has fewer items than minItems");
        }
        if bound("maxItems").is_some_and(|max| count > max) {
            return fail(at, "array has more items than maxItems");
        }
        let prefix = schema
            .get("prefixItems")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for (index, item) in items.iter().enumerate() {
            let path = child(at, &index.to_string());
            match prefix.get(index) {
                Some(position) => self.check(position, item, &path, depth)?,
                None => {
                    if let Some(rest) = schema.get("items") {
                        self.check(rest, item, &path, depth)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ticket() -> Value {
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["id", "product", "severity", "tags"],
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "product": {"type": ["string", "null"], "enum": ["app", "api", null]},
                "severity": {"type": ["integer", "null"], "enum": [1, 2, 3, null]},
                "tags": {"type": "array", "items": {"$ref": "#/$defs/tag"}, "maxItems": 2}
            },
            "$defs": {"tag": {"type": "string"}}
        })
    }

    #[test]
    fn a_conforming_answer_passes() {
        let answer = json!({"id": "T-1", "product": null, "severity": 2.0, "tags": ["ios"]});
        assert_eq!(check(&ticket(), &answer), Ok(()));
    }

    #[test]
    fn each_structural_violation_is_named_by_path_and_rule_without_the_value() {
        let cases = [
            (
                json!({"id": "T-1", "product": "app", "severity": 1}),
                "",
                "missing required",
            ),
            (
                json!({"id": "T-1", "product": "app", "severity": 1, "tags": [], "x": 1}),
                "",
                "\"x\" is not allowed",
            ),
            (
                json!({"id": 7, "product": "app", "severity": 1, "tags": []}),
                "/id",
                "expected type string",
            ),
            (
                json!({"id": "T-1", "product": "web", "severity": 1, "tags": []}),
                "/product",
                "enum",
            ),
            (
                json!({"id": "T-1", "product": "app", "severity": 1.5, "tags": []}),
                "/severity",
                "expected type",
            ),
            (
                json!({"id": "T-1", "product": "app", "severity": 1, "tags": [3]}),
                "/tags/0",
                "expected type string",
            ),
            (
                json!({"id": "T-1", "product": "app", "severity": 1, "tags": ["a", "b", "c"]}),
                "/tags",
                "maxItems",
            ),
            (
                json!({"id": "", "product": "app", "severity": 1, "tags": []}),
                "/id",
                "minLength",
            ),
        ];
        for (answer, at, rule) in cases {
            let violation = check(&ticket(), &answer).expect_err(&answer.to_string());
            assert_eq!(violation.at, at, "{answer}");
            assert!(violation.rule.contains(rule), "{answer}: {violation}");
            assert!(
                !violation.to_string().contains("web"),
                "no values: {violation}"
            );
        }
    }

    #[test]
    fn combinators_refs_and_booleans() {
        let schema = json!({"anyOf": [{"type": "string"}, {"$ref": "#/$defs/n"}],
                            "$defs": {"n": {"type": "integer", "minimum": 0}}});
        assert!(check(&schema, &json!("x")).is_ok());
        assert!(check(&schema, &json!(3)).is_ok());
        assert!(check(&schema, &json!(-1)).is_err());
        assert!(
            check(
                &json!({"oneOf": [{"type": "integer"}, {"type": "number"}]}),
                &json!(1)
            )
            .is_err()
        );
        assert!(check(&json!({"not": {"type": "null"}}), &json!(null)).is_err());
        assert!(check(&json!(false), &json!(1)).is_err());
        assert!(check(&json!(true), &json!(1)).is_ok());
        assert!(check(&json!({"const": 1}), &json!(1.0)).is_ok());
    }

    #[test]
    fn a_recursive_schema_checks_deep_values_and_a_cycle_fails_loudly() {
        let tree = json!({"type": "object", "additionalProperties": false, "required": ["kids"],
                          "properties": {"kids": {"type": "array", "items": {"$ref": "#"}}}});
        assert!(
            check(
                &tree,
                &json!({"kids": [{"kids": []}, {"kids": [{"kids": []}]}]})
            )
            .is_ok()
        );
        assert!(check(&tree, &json!({"kids": [{"kids": [{}]}]})).is_err());
        let cycle = json!({"$ref": "#"});
        let violation = check(&cycle, &json!(1)).unwrap_err();
        assert!(violation.rule.contains("too deep"), "{violation}");
        let dangling = json!({"$ref": "#/$defs/missing"});
        assert!(check(&dangling, &json!(1)).is_err());
    }
}
