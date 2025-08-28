use alohomora::bbox::BBox;
use alohomora::context::UnprotectedContext;
use alohomora::policy::{Reason, SimplePolicy};
use alohomora::testing::TestPolicy;
use serde::Serialize;
use tahini_tarpc::{TahiniEnum, TahiniType, TahiniVariantsEnum};

#[derive(Serialize)]
pub struct MyPolicy {
    pub x: u32,
    pub y: String,
}
impl SimplePolicy for MyPolicy {
    fn simple_name(&self) -> String {
        todo!()
    }
    fn simple_check(&self, context: &UnprotectedContext, reason: Reason<'_>) -> bool {
        todo!()
    }
    fn simple_join_direct(&mut self, other: &mut Self) {
        todo!()
    }
}

#[derive(TahiniType)]
pub struct SimpleStruct1 {
    pub f1: String,
    pub f2: BBox<u32, TestPolicy<MyPolicy>>,
}

#[test]
fn test_simple_struct() {
    let s = SimpleStruct1 {
        f1: String::from("hello"),
        f2: BBox::new(
            10,
            TestPolicy::new(MyPolicy {
                x: 1,
                y: String::from("world"),
            }),
        ),
    };

    // Turn to enum.
    let e = s.to_tahini_enum();

    // Check enum is what we expect.
    assert!(matches!(e, TahiniEnum::Struct(_, _)));
    if let TahiniEnum::Struct(name, mut fields) = e {
        assert_eq!(name, "SimpleStruct1");
        assert!(matches!(fields.get("f1").unwrap(), TahiniEnum::Value(_)));
        assert!(matches!(fields.get("f2").unwrap(), TahiniEnum::BBox(_)));

        if let TahiniEnum::Value(v) = fields.remove("f1").unwrap() {
            assert_eq!(v.upcast_any().downcast_ref::<String>().unwrap(), "hello");
        }
        if let TahiniEnum::BBox(b) = fields.remove("f2").unwrap() {
            let b = b
                .specialize_policy::<TestPolicy<MyPolicy>>()
                .map_err(|_| ())
                .unwrap();
            assert_eq!(b.policy().policy().x, 1);
            assert_eq!(b.policy().policy().y, String::from("world"));
            assert_eq!(
                *b.discard_box().upcast_any().downcast_ref::<u32>().unwrap(),
                10
            );
        }
    }
}

#[derive(TahiniType)]
pub struct NestedStruct {
    pub b1: BBox<u32, TestPolicy<MyPolicy>>,
    pub b2: String,
    pub b3: SimpleStruct1,
}

#[test]
fn test_nested_struct() {
    let s = NestedStruct {
        b1: BBox::new(
            1020,
            TestPolicy::new(MyPolicy {
                x: 5,
                y: String::from("nested policy"),
            }),
        ),
        b2: String::from("nested"),
        b3: SimpleStruct1 {
            f1: String::from("hello"),
            f2: BBox::new(
                10,
                TestPolicy::new(MyPolicy {
                    x: 1,
                    y: String::from("world"),
                }),
            ),
        },
    };

    // Turn to enum.
    let e = s.to_tahini_enum();

    // Check enum is what we expect.
    assert!(matches!(e, TahiniEnum::Struct(_, _)));
    if let TahiniEnum::Struct(name, mut fields) = e {
        assert_eq!(name, "NestedStruct");
        assert!(matches!(fields.get("b1").unwrap(), TahiniEnum::BBox(_)));
        assert!(matches!(fields.get("b2").unwrap(), TahiniEnum::Value(_)));
        assert!(matches!(
            fields.get("b3").unwrap(),
            TahiniEnum::Struct(_, _)
        ));

        if let TahiniEnum::BBox(b) = fields.remove("b1").unwrap() {
            let b = b
                .specialize_policy::<TestPolicy<MyPolicy>>()
                .map_err(|_| ())
                .unwrap();
            assert_eq!(b.policy().policy().x, 5);
            assert_eq!(b.policy().policy().y, String::from("nested policy"));
            assert_eq!(
                *b.discard_box().upcast_any().downcast_ref::<u32>().unwrap(),
                1020
            );
        }
        if let TahiniEnum::Value(v) = fields.remove("b2").unwrap() {
            assert_eq!(v.upcast_any().downcast_ref::<String>().unwrap(), "nested");
        }

        let e = fields.remove("b3").unwrap();
        assert!(matches!(e, TahiniEnum::Struct(_, _)));
        if let TahiniEnum::Struct(name, mut fields) = e {
            assert_eq!(name, "SimpleStruct1");
            assert!(matches!(fields.get("f1").unwrap(), TahiniEnum::Value(_)));
            assert!(matches!(fields.get("f2").unwrap(), TahiniEnum::BBox(_)));

            if let TahiniEnum::Value(v) = fields.remove("f1").unwrap() {
                assert_eq!(v.upcast_any().downcast_ref::<String>().unwrap(), "hello");
            }
            if let TahiniEnum::BBox(b) = fields.remove("f2").unwrap() {
                let b = b
                    .specialize_policy::<TestPolicy<MyPolicy>>()
                    .map_err(|_| ())
                    .unwrap();
                assert_eq!(b.policy().policy().x, 1);
                assert_eq!(b.policy().policy().y, String::from("world"));
                assert_eq!(
                    *b.discard_box().upcast_any().downcast_ref::<u32>().unwrap(),
                    10
                );
            }
        }
    }
}

#[derive(TahiniType)]
pub enum MyEnum {
    AUnitVariant,
    ASimpleVariant(u32),
    ABBoxVariant(BBox<u32, TestPolicy<MyPolicy>>),
    AStructVariant(SimpleStruct1),
}

#[test]
fn test_enum_unit() {
    let s = MyEnum::AUnitVariant;
    let e = s.to_tahini_enum();

    assert!(matches!(e, TahiniEnum::Enum(_, _, _, _)));
    if let TahiniEnum::Enum(name, variant, variant_name, fields) = e {
        assert_eq!(name, "MyEnum");
        assert_eq!(variant, 0);
        assert_eq!(variant_name, "AUnitVariant");
        assert!(matches!(fields, TahiniVariantsEnum::Unit));
    }
}

#[test]
fn test_enum_simple() {
    let s = MyEnum::ASimpleVariant(55);
    let e = s.to_tahini_enum();

    assert!(matches!(e, TahiniEnum::Enum(_, _, _, _)));
    if let TahiniEnum::Enum(name, variant, variant_name, fields) = e {
        assert_eq!(name, "MyEnum");
        assert_eq!(variant, 1);
        assert_eq!(variant_name, "ASimpleVariant");
        assert!(matches!(fields, TahiniVariantsEnum::NewType(_)));
        if let TahiniVariantsEnum::NewType(e) = fields {
            assert!(matches!(*e, TahiniEnum::Value(_)));
            if let TahiniEnum::Value(v) = *e {
                assert_eq!(*v.upcast_any().downcast_ref::<u32>().unwrap(), 55);
            }
        }
    }
}

#[test]
fn test_enum_bbox() {
    let s = MyEnum::ABBoxVariant(BBox::new(
        71,
        TestPolicy::new(MyPolicy {
            x: 1,
            y: String::from("world"),
        }),
    ));
    let e = s.to_tahini_enum();

    assert!(matches!(e, TahiniEnum::Enum(_, _, _, _)));
    if let TahiniEnum::Enum(name, variant, variant_name, fields) = e {
        assert_eq!(name, "MyEnum");
        assert_eq!(variant, 2);
        assert_eq!(variant_name, "ABBoxVariant");
        assert!(matches!(fields, TahiniVariantsEnum::NewType(_)));
        if let TahiniVariantsEnum::NewType(e) = fields {
            assert!(matches!(*e, TahiniEnum::BBox(_)));
            if let TahiniEnum::BBox(b) = *e {
                let b = b
                    .specialize_policy::<TestPolicy<MyPolicy>>()
                    .map_err(|_| ())
                    .unwrap();
                assert_eq!(b.policy().policy().x, 1);
                assert_eq!(b.policy().policy().y, String::from("world"));
                assert_eq!(
                    *b.discard_box().upcast_any().downcast_ref::<u32>().unwrap(),
                    71
                );
            }
        }
    }
}

#[test]
fn test_enum_struct() {
    let s = MyEnum::AStructVariant(SimpleStruct1 {
        f1: String::from("hello"),
        f2: BBox::new(
            10,
            TestPolicy::new(MyPolicy {
                x: 1,
                y: String::from("world"),
            }),
        ),
    });
    let e = s.to_tahini_enum();

    assert!(matches!(e, TahiniEnum::Enum(_, _, _, _)));
    if let TahiniEnum::Enum(name, variant, variant_name, fields) = e {
        assert_eq!(name, "MyEnum");
        assert_eq!(variant, 3);
        assert_eq!(variant_name, "AStructVariant");
        assert!(matches!(fields, TahiniVariantsEnum::NewType(_)));
        if let TahiniVariantsEnum::NewType(e) = fields {
            assert!(matches!(*e, TahiniEnum::Struct(_, _)));
            if let TahiniEnum::Struct(name, mut fields) = *e {
                assert_eq!(name, "SimpleStruct1");
                assert!(matches!(fields.get("f1").unwrap(), TahiniEnum::Value(_)));
                assert!(matches!(fields.get("f2").unwrap(), TahiniEnum::BBox(_)));

                if let TahiniEnum::Value(v) = fields.remove("f1").unwrap() {
                    assert_eq!(v.upcast_any().downcast_ref::<String>().unwrap(), "hello");
                }
                if let TahiniEnum::BBox(b) = fields.remove("f2").unwrap() {
                    let b = b
                        .specialize_policy::<TestPolicy<MyPolicy>>()
                        .map_err(|_| ())
                        .unwrap();
                    assert_eq!(b.policy().policy().x, 1);
                    assert_eq!(b.policy().policy().y, String::from("world"));
                    assert_eq!(
                        *b.discard_box().upcast_any().downcast_ref::<u32>().unwrap(),
                        10
                    );
                }
            }
        }
    }
}
