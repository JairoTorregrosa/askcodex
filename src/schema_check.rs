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
//! - local `$ref` (`#`, `#/$defs/...`, any JSON pointer into the schema);
//!   under a draft-07 or older `$schema`, the keywords beside a `$ref` are
//!   ignored, as those drafts require.
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
    let dialect = schema.get("$schema").and_then(Value::as_str).unwrap_or("");
    let ref_replaces_siblings = ["draft-03", "draft-04", "draft-06", "draft-07"]
        .iter()
        .any(|draft| dialect.contains(draft));
    Checker {
        root: schema,
        ref_replaces_siblings,
    }
    .check(schema, answer, "", 0)
}

struct Checker<'a> {
    root: &'a Value,
    /// Draft-07 and older: a `$ref` makes every keyword beside it inert.
    ref_replaces_siblings: bool,
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

/// JSON-Schema numeric equality: by value, so `1` equals `1.0`.
fn same_number(a: &serde_json::Number, b: &serde_json::Number) -> bool {
    compare_numbers(a, b) == Some(std::cmp::Ordering::Equal)
}

/// A JSON number as an exact integer, when it is one: i64/u64 literals,
/// and floats with no fraction (every f64 beyond 2^53 is one) that fit.
fn as_exact_integer(n: &serde_json::Number) -> Option<i128> {
    if let Some(i) = n.as_i64() {
        return Some(i128::from(i));
    }
    if let Some(u) = n.as_u64() {
        return Some(i128::from(u));
    }
    let f = n.as_f64()?;
    (f.fract() == 0.0 && f.abs() < 1e38).then_some(f as i128)
}

/// Order two numbers without rounding whole numbers through f64: above
/// 2^53 distinct integers share an f64, so `18446744073709551615` would
/// compare equal to `18446744073709551614`, and `9007199254740993` to
/// `9007199254740992.0`. Only a pair with a real fraction compares as f64,
/// and fractions exist only below 2^53, where f64 holds integers exactly.
fn compare_numbers(a: &serde_json::Number, b: &serde_json::Number) -> Option<std::cmp::Ordering> {
    match (as_exact_integer(a), as_exact_integer(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
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
            if self.ref_replaces_siblings {
                return Ok(());
            }
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
        // A branch that uses a keyword this module leaves to the backend
        // (`pattern`, `format`, ...) can pass here and still fail there, so
        // a pass is only optimistic. That is safe for `allOf` and `anyOf`
        // (they only get more lenient), but would turn `not` and the
        // "exactly one" of `oneOf` into false rejections: those checks run
        // only over fully checkable branches.
        if let Some(one) = branches("oneOf") {
            let matched = one
                .iter()
                .filter(|branch| self.check(branch, value, at, depth).is_ok())
                .count();
            let exact = one.iter().all(|branch| self.fully_checked(branch, 0));
            if matched == 0 || (exact && matched != 1) {
                return fail(
                    at,
                    format!("value matches {matched} oneOf branches, not exactly 1"),
                );
            }
        }
        if let Some(not) = schema.get("not")
            && self.fully_checked(not, 0)
            && self.check(not, value, at, depth).is_ok()
        {
            return fail(at, "value matches the schema under not");
        }
        Ok(())
    }

    /// Whether every keyword in `schema`, and in every subschema it can
    /// reach, is one this module evaluates (or an annotation). A cycle or
    /// a schema too deep to walk counts as not fully checked.
    fn fully_checked(&self, schema: &Value, depth: usize) -> bool {
        const EVALUATED: [&str; 20] = [
            "type",
            "properties",
            "required",
            "additionalProperties",
            "items",
            "prefixItems",
            "minItems",
            "maxItems",
            "enum",
            "const",
            "anyOf",
            "allOf",
            "oneOf",
            "not",
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "minLength",
            "maxLength",
        ];
        const ANNOTATIONS: [&str; 14] = [
            "writeOnly",
            "additionalItems",
            "$ref",
            "$defs",
            "definitions",
            "$schema",
            "$id",
            "$comment",
            "title",
            "description",
            "default",
            "examples",
            "deprecated",
            "readOnly",
        ];
        if depth > MAX_DEPTH {
            return false;
        }
        let schema = match schema {
            Value::Bool(_) => return true,
            Value::Object(schema) => schema,
            _ => return false,
        };
        let next = depth + 1;
        let reference = |reference: Option<&str>| match reference {
            Some(reference) => match reference
                .strip_prefix('#')
                .and_then(|p| self.root.pointer(p))
            {
                Some(target) => self.fully_checked(target, next),
                None => false,
            },
            None => true,
        };
        let target = schema.get("$ref").and_then(Value::as_str);
        if self.ref_replaces_siblings && target.is_some() {
            return reference(target);
        }
        let known = |key: &str| EVALUATED.contains(&key) || ANNOTATIONS.contains(&key);
        if !schema.keys().all(|key| known(key)) {
            return false;
        }
        // A bound in a shape the checker does not read is not evaluated.
        let unread_bound = schema.iter().any(|(key, bound)| match key.as_str() {
            "exclusiveMinimum" | "exclusiveMaximum" => !bound.is_number() && !bound.is_boolean(),
            "minimum" | "maximum" | "minLength" | "maxLength" | "minItems" | "maxItems" => {
                !bound.is_number()
            }
            _ => false,
        });
        if unread_bound {
            return false;
        }
        let subschemas = schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|properties| properties.values())
            .chain(
                ["items", "additionalItems", "additionalProperties", "not"]
                    .iter()
                    .filter_map(|k| schema.get(*k))
                    .filter(|sub| !sub.is_array()),
            )
            .chain(
                ["items", "prefixItems", "anyOf", "allOf", "oneOf"]
                    .iter()
                    .filter_map(|k| schema.get(*k).and_then(Value::as_array))
                    .flatten(),
            );
        reference(target)
            && subschemas
                .into_iter()
                .all(|sub| self.fully_checked(sub, next))
    }

    fn check_bounds(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        at: &str,
    ) -> Result<(), Violation> {
        use std::cmp::Ordering::{Equal, Greater, Less};
        if let Value::Number(number) = value {
            // `None` (no bound, or a bound that is not a number) passes.
            let against = |key| match schema.get(key) {
                Some(Value::Number(bound)) => compare_numbers(number, bound),
                _ => None,
            };
            // Draft-07 and earlier: `exclusiveMinimum: true` makes `minimum`
            // exclusive.
            let draft_07_exclusive = |key| schema.get(key) == Some(&Value::Bool(true));
            match against("minimum") {
                Some(Less) => return fail(at, "number is below minimum"),
                Some(Equal) if draft_07_exclusive("exclusiveMinimum") => {
                    return fail(at, "number is not above exclusiveMinimum");
                }
                _ => {}
            }
            match against("maximum") {
                Some(Greater) => return fail(at, "number is above maximum"),
                Some(Equal) if draft_07_exclusive("exclusiveMaximum") => {
                    return fail(at, "number is not below exclusiveMaximum");
                }
                _ => {}
            }
            if against("exclusiveMinimum").is_some_and(|o| o != Greater) {
                return fail(at, "number is not above exclusiveMinimum");
            }
            if against("exclusiveMaximum").is_some_and(|o| o != Less) {
                return fail(at, "number is not below exclusiveMaximum");
            }
        }
        let bound = |key| schema.get(key).and_then(Value::as_f64);
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
            // Keys the schema declares may appear in a path; a key only the
            // answer has may be personal data (an email as a property
            // name), so it never reaches a message.
            let declared = properties.is_some_and(|p| p.contains_key(key));
            let path = if declared {
                child(at, key)
            } else {
                format!("{at}/*")
            };
            // A key outside `properties` may still match a `patternProperties`
            // regex, which is left to the backend: leave such keys unchecked.
            let patterned = schema.contains_key("patternProperties");
            match properties.and_then(|p| p.get(key)) {
                Some(property) => self.check(property, member, &path, depth)?,
                None if patterned => {}
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => {
                        return fail(at, "a property the schema does not declare is not allowed");
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
        // Draft-07 spelled tuples as an `items` array (with
        // `additionalItems` for the rest); 2020-12 uses `prefixItems` and a
        // single-schema `items`. Both are read rather than misreading the
        // older form as a malformed schema.
        let (prefix, rest) = match schema.get("items") {
            Some(Value::Array(tuple)) => (tuple.as_slice(), schema.get("additionalItems")),
            rest => (
                schema
                    .get("prefixItems")
                    .and_then(Value::as_array)
                    .map_or(&[][..], Vec::as_slice),
                rest,
            ),
        };
        for (index, item) in items.iter().enumerate() {
            let path = child(at, &index.to_string());
            match prefix.get(index) {
                Some(position) => self.check(position, item, &path, depth)?,
                None => {
                    if let Some(rest) = rest {
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
                "does not declare is not allowed",
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
    fn keywords_left_to_the_backend_never_cause_a_false_rejection() {
        // `pattern` is not evaluated here, so `not` over it must not be
        // read as "matched", and `oneOf` cannot demand exactly one.
        let not_pattern = json!({"type": "string", "not": {"pattern": "^x"}});
        assert!(check(&not_pattern, &json!("abc")).is_ok());
        let one_of = json!({"oneOf": [{"type": "string", "pattern": "^a"},
                                      {"type": "string", "pattern": "^b"}]});
        assert!(check(&one_of, &json!("abc")).is_ok());
        assert!(
            check(&one_of, &json!(7)).is_err(),
            "no branch can match a number"
        );
        // Fully checkable branches keep the exact semantics.
        assert!(check(&json!({"not": {"type": "string"}}), &json!("abc")).is_err());
        let recursive =
            json!({"$defs": {"t": {"not": {"$ref": "#/$defs/t"}}}, "$ref": "#/$defs/t"});
        let _ = check(&recursive, &json!(1));
        // A key that may match a `patternProperties` regex is never an
        // "additional" property here; declared properties stay checked.
        let patterned = json!({"type": "object", "additionalProperties": false,
                               "properties": {"id": {"type": "integer"}},
                               "patternProperties": {"^S_": {"type": "string"}}});
        assert!(check(&patterned, &json!({"id": 1, "S_name": "ok"})).is_ok());
        assert!(check(&patterned, &json!({"id": "1"})).is_err());
        // Draft-07 boolean exclusive bounds, alone and under `not`; a bound
        // the checker cannot read never makes `not` reject.
        let above_5 = json!({"minimum": 5, "exclusiveMinimum": true});
        assert!(check(&above_5, &json!(5)).is_err());
        assert!(check(&above_5, &json!(6)).is_ok());
        let not_above_5 = json!({"not": above_5});
        assert!(check(&not_above_5, &json!(5)).is_ok());
        assert!(check(&not_above_5, &json!(6)).is_err());
        let below_5 = json!({"maximum": 5, "exclusiveMaximum": true});
        assert!(check(&below_5, &json!(5)).is_err());
        assert!(check(&json!({"not": {"minimum": "5"}}), &json!(1)).is_ok());
    }

    #[test]
    fn draft_07_ignores_the_keywords_beside_a_ref() {
        let sibling = |dialect: &str| {
            json!({"$schema": dialect, "$ref": "#/definitions/n", "type": "string",
                   "definitions": {"n": {"type": "integer"}}})
        };
        let draft_07 = sibling("http://json-schema.org/draft-07/schema#");
        assert!(check(&draft_07, &json!(1)).is_ok());
        assert!(
            check(&draft_07, &json!("1")).is_err(),
            "the $ref still applies"
        );
        // 2019-09 and later apply both, as does a schema with no `$schema`.
        let current = sibling("https://json-schema.org/draft/2020-12/schema");
        assert!(check(&current, &json!(1)).is_err());
        let mut undeclared = sibling("");
        undeclared.as_object_mut().unwrap().remove("$schema");
        assert!(check(&undeclared, &json!(1)).is_err());
    }

    #[test]
    fn keys_only_the_answer_has_never_reach_a_message() {
        let closed = json!({"type": "object", "additionalProperties": false, "properties": {}});
        let violation = check(&closed, &json!({"ana@example.com": 1})).unwrap_err();
        assert!(!violation.to_string().contains("ana@"), "{violation}");
        let typed = json!({"type": "object", "additionalProperties": {"type": "string"}});
        let violation = check(&typed, &json!({"ana@example.com": 1})).unwrap_err();
        assert_eq!(violation.at, "/*");
        assert!(!violation.to_string().contains("ana@"), "{violation}");
    }

    #[test]
    fn draft_07_tuple_items_are_read_as_tuples() {
        let tuple = json!({"type": "array", "items": [{"type": "string"}, {"type": "integer"}]});
        assert!(check(&tuple, &json!(["a", 1, true])).is_ok());
        assert!(check(&tuple, &json!([1, "a"])).is_err());
        let closed = json!({"items": [{"type": "string"}], "additionalItems": false});
        assert!(check(&closed, &json!(["a", "b"])).is_err());
    }

    #[test]
    fn numeric_bounds_compare_wide_integers_exactly() {
        let schema = json!({"type": "integer", "maximum": 18446744073709551614u64});
        assert!(check(&schema, &json!(18446744073709551615u64)).is_err());
        assert!(check(&schema, &json!(18446744073709551614u64)).is_ok());
        let schema = json!({"exclusiveMinimum": -9223372036854775807i64});
        assert!(check(&schema, &json!(-9223372036854775808i64)).is_err());
        assert!(check(&schema, &json!(18446744073709551615u64)).is_ok());
        assert!(check(&json!({"minimum": 0.5}), &json!(0)).is_err());
        assert!(check(&json!({"maximum": 2}), &json!(2.0)).is_ok());
        // Mixed integer/float equality is exact too.
        let pinned = json!({"const": 9007199254740992.0});
        assert!(check(&pinned, &json!(9007199254740993u64)).is_err());
        assert!(
            check(
                &json!({"enum": [9007199254740992.0]}),
                &json!(9007199254740992u64)
            )
            .is_ok()
        );
        assert!(check(&json!({"const": 1.5}), &json!(1.5)).is_ok());
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
