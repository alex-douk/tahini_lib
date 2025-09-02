use crate::traits::{TahiniDataType, TahiniPolicy, TahiniType};

use alohomora::bbox::BBox;
use alohomora::extensions::SesameExtension;

use serde::ser::{SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTupleVariant};
use std::collections::HashMap;
use std::marker::PhantomData;

// TODO(babman): this enum goes away when coercion is in Sesame.
pub enum TahiniEnum {
    Value(TahiniDataType),
    BBox(BBox<TahiniDataType, TahiniPolicy>),
    Vec(Vec<TahiniEnum>),
    Struct(&'static str, HashMap<&'static str, TahiniEnum>),
    Enum(&'static str, u32, &'static str, TahiniVariantsEnum),
    Option(Option<Box<TahiniEnum>>),
    Result(Result<Box<TahiniEnum>, Box<TahiniEnum>>),
}

pub enum TahiniVariantsEnum {
    Unit,
    Struct(HashMap<&'static str, TahiniEnum>),
    NewType(Box<TahiniEnum>),
    Tuple(Vec<TahiniEnum>),
}

// Serializes the TahiniEnum using a Sesame extension.
struct BBoxSerializer<S: serde::Serializer>(S);

impl<S: serde::Serializer> SesameExtension<TahiniDataType, TahiniPolicy, Result<S::Ok, S::Error>>
    for BBoxSerializer<S>
where
    S: serde::Serializer,
{
    fn apply(self, data: TahiniDataType, policy: TahiniPolicy) -> Result<S::Ok, S::Error> {
        self.apply_ref(&data, &policy)
    }

    fn apply_ref(self, data: &TahiniDataType, policy: &TahiniPolicy) -> Result<S::Ok, S::Error> {
        let mut bbox_ser = self.0.serialize_struct("BBox", 2)?;
        bbox_ser.serialize_field("fb", data.upcast_serialize())?;
        bbox_ser.serialize_field("p", policy.inner().upcast_serialize())?;
        bbox_ser.end()
    }
}

fn serialize_enum<S: serde::Serializer>(
    enum_name: &'static str,
    index: &u32,
    variant_name: &'static str,
    variant: &TahiniVariantsEnum,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match variant {
        TahiniVariantsEnum::Struct(map) => {
            let mut struct_ser =
                serializer.serialize_struct_variant(enum_name, *index, variant_name, map.len())?;
            for (k, v) in map.iter() {
                struct_ser.serialize_field(k, &PrivEnumWrapper(v))?;
            }
            struct_ser.end()
        }
        TahiniVariantsEnum::NewType(inner) => serializer.serialize_newtype_variant(
            enum_name,
            *index,
            variant_name,
            &PrivEnumWrapper(&(*inner)),
        ),
        TahiniVariantsEnum::Unit => {
            serializer.serialize_unit_variant(enum_name, *index, variant_name)
        }
        TahiniVariantsEnum::Tuple(iter) => {
            let mut tuple_ser =
                serializer.serialize_tuple_variant(enum_name, *index, variant_name, iter.len())?;
            for e in iter.iter() {
                tuple_ser.serialize_field(&PrivEnumWrapper(e))?;
            }
            tuple_ser.end()
        }
    }
}

//Private struct for specific TahiniEnum leaves.
struct PrivEnumWrapper<'a>(&'a TahiniEnum);
impl<'a> serde::Serialize for PrivEnumWrapper<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            TahiniEnum::Value(val) => erased_serde::serialize(val.upcast_serialize(), serializer),
            TahiniEnum::BBox(bbox) => {
                let bbox_ser = BBoxSerializer(serializer);
                bbox.apply_extension_ref(bbox_ser)
            }
            TahiniEnum::Vec(vec) => {
                let mut vec_ser = serializer.serialize_seq(Some(vec.len()))?;
                for e in vec.iter() {
                    vec_ser.serialize_element(&PrivEnumWrapper(e))?;
                }
                vec_ser.end()
            }
            TahiniEnum::Struct(struct_name, map) => {
                let mut struct_ser = serializer.serialize_struct(struct_name, map.len())?;
                for (k, v) in map.iter() {
                    struct_ser.serialize_field(k, &PrivEnumWrapper(v))?;
                }
                struct_ser.end()
            }
            TahiniEnum::Enum(enum_name, idx, name, val) => {
                serialize_enum(*enum_name, idx, *name, val, serializer)
            }
            TahiniEnum::Option(opt) => match opt {
                None => None::<PrivEnumWrapper>.serialize(serializer),
                Some(val) => Some(PrivEnumWrapper(&val)).serialize(serializer),
            },
            TahiniEnum::Result(res) => res
                .as_ref()
                .map(|v| PrivEnumWrapper(v))
                .map_err(|e| PrivEnumWrapper(e))
                .serialize(serializer),
        }
    }
}

//Only messy part here is to have two different wrappers operating the same function
//The real reason is that it gives explicit typing to our structs.
//It's open to debate whether we want to have two layers :shrug:

pub struct TahiniSafeWrapper<T: TahiniType> {
    e: TahiniEnum,
    t: PhantomData<T>,
}
impl<T: TahiniType> TahiniSafeWrapper<T> {
    pub fn new(t: T) -> Self {
        Self {
            e: t.to_tahini_enum(),
            t: PhantomData,
        }
    }
}
impl<T: TahiniType + Clone> serde::Serialize for TahiniSafeWrapper<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        PrivEnumWrapper(&self.e).serialize(serializer)
    }
}
