use crate::traits::{TahiniDataType, TahiniPolicy, TahiniType};

use sesame::extensions::{SesameExtension, SesameRefExtension, UncheckedSesameExtension};
use sesame::pcon::{self, PCon};

use serde::ser::{SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTupleVariant};
use std::collections::HashMap;
use std::marker::PhantomData;

// TODO(babman): this enum goes away when coercion is in Sesame.
pub enum TahiniEnum {
    Value(TahiniDataType),
    PCon(PCon<TahiniDataType, TahiniPolicy>),
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
// impl<S: serde::Serializer> SesameExtension<TahiniDataType, TahiniPolicy, Result<S::Ok, S::Error>>
//     for PConSerializer<S>
// where
//     S: serde::Serializer,
// {
//     fn apply(self, data: TahiniDataType, policy: TahiniPolicy) -> Result<S::Ok, S::Error> {
//         self.apply_ref(&data, &policy)
//     }
// }
//

// impl<'a, S: serde::Serializer> SesameExtension<TahiniDataType, TahiniPolicy, Result<S::Ok, S::Error>> for &mut PConSerializer<S> {
//     fn apply(&mut self, data: TahiniDataType, policy: TahiniPolicy) -> Result<S::Ok, S::Error> {
//         
//     }
//
// }

//Current issue is that the sesame extension API takes the extension by mutable reference
//NOT by value.
//However, the serializer is consumed by value for serialize_struct.
//I can't dereference it smh.
//What are the options here? Usually you would have a Clone trait bound to ensure everything works
//smooth here.
//I can't have that. 


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
            TahiniEnum::PCon(bbox) => {
                //Because Sesame's APIs take by reference the extension object, we can't actually
                //use a wrapper type that holds a serializer, as the serializer APIs are all by
                //value.
                struct PConSerializer;
                impl<'a>
                    SesameRefExtension<'a, TahiniDataType, TahiniPolicy, (&'a TahiniDataType, &'a TahiniPolicy)>
                    for PConSerializer
                {
                    fn apply_ref(&mut self, data: &'a TahiniDataType, policy: &'a TahiniPolicy) -> (&'a TahiniDataType, &'a TahiniPolicy){
                        (data, policy)
                    }
                }
                impl UncheckedSesameExtension for PConSerializer {}
                let mut extension = PConSerializer;
                let (t, p) = bbox.unchecked_extension_ref(&mut extension);
                let mut pcon_ser = serializer.serialize_struct("PCon", 2)?;
                pcon_ser.serialize_field("fb", t.upcast_serialize())?;
                pcon_ser.serialize_field("p", p.inner().upcast_serialize())?;
                pcon_ser.end()
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
