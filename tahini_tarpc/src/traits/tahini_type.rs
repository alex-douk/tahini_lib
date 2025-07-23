use std::collections::HashMap;

use erased_serde::serialize_trait_object;
use serde::{Deserialize, Serialize};

use alohomora::bbox::BBox;
// use alohomora::context::UnprotectedContext;
use alohomora::policy::{Policy, TahiniPolicy};
// use alohomora::policy::Reason;
use crate::enums::TahiniEnum;

struct BBoxEnumator;

//TODO(douk): This should disappear with the new SesameType.
impl<T, P> alohomora::extension::SesamePConExtension<T, P, TahiniEnum> for BBoxEnumator 
where 
        T: Serialize + for<'de> Deserialize<'de> + Clone + Send + 'static,
        P: Policy + Clone + Serialize + for<'de> Deserialize<'de> + 'static,
    {
    fn apply(self, data: T, policy: P) -> TahiniEnum {
        let anybox = Box::new(data) as Box<dyn erased_serde::Serialize>;
        TahiniEnum::BBox(BBox::new(anybox, TahiniPolicy::new(policy)))
    }

    fn apply_ref(self, data: &T, policy: &P) -> TahiniEnum {
        let anybox = Box::new(data.clone()) as Box<dyn erased_serde::Serialize>;
        TahiniEnum::BBox(BBox::new(anybox, TahiniPolicy::new(policy.clone())))
        
    }

}

pub trait TahiniType: Send {
    fn to_tahini_enum(&self) -> TahiniEnum;
    // fn tahini_policy_check(
    //     &self,
    //     _members_fmt: &String,
    //     _context: &UnprotectedContext,
    //     _reason: &Reason,
    // ) -> bool {
    //     true
    // }
}

pub trait TahiniError: erased_serde::Serialize + std::error::Error {}

serialize_trait_object!(TahiniError);

impl<
        T: Serialize + for<'de> Deserialize<'de> + Clone + Send + 'static,
        P: Policy + Clone + Serialize + for<'de> Deserialize<'de> + 'static,
    > TahiniType for BBox<T, P>
{
    fn to_tahini_enum(&self) -> TahiniEnum {
        let copy = self.clone();
        let enumator = BBoxEnumator;
        copy.apply_extension(enumator)
    }
    // fn tahini_policy_check(
    //     &self,
    //     _members_fmt: &String,
    //     context: &UnprotectedContext,
    //     reason: &Reason,
    // ) -> bool {
    //     self.policy().check(context, reason.clone())
    // }
}



impl<T: TahiniType + Clone + 'static> TahiniType for Option<T> {
    fn to_tahini_enum(&self) -> TahiniEnum {
        TahiniEnum::Option(self.as_ref().map(|x| Box::new(x.to_tahini_enum())))
        // match &self {
        //
        //     None => TahiniEnum::Option(None::<T>),
        //     //Works for primitive types but not for BBox's
        //     Some(x) => TahiniEnum::Value(Box::new(Some(x.clone())))
        // }
    }
    // fn tahini_policy_check(
    //     &self,
    //     members_fmt: &String,
    //     context: &UnprotectedContext,
    //     reason: &Reason,
    // ) -> bool {
    //     match self {
    //         Some(t) => t.tahini_policy_check(&members_fmt, context, &reason),
    //         None => true,
    //     }
    // }
}

impl<T: TahiniType + Clone + 'static, E: TahiniError + Send + 'static + Clone> TahiniType
    for Result<T, E>
{
    fn to_tahini_enum(&self) -> TahiniEnum {
        TahiniEnum::Result(
            self.as_ref()
                .map(|x| Box::new(x.to_tahini_enum()))
                .map_err(|x| Box::new(x.clone()) as Box<dyn TahiniError>),
        )
    }

    // fn tahini_policy_check(
    //     &self,
    //     members_fmt: &String,
    //     context: &UnprotectedContext,
    //     reason: &Reason,
    // ) -> bool {
    //     match self {
    //         Ok(r) => r.tahini_policy_check(members_fmt, context, reason),
    //         Err(_) => true,
    //     }
    // }
}

impl<T: TahiniType + Clone + 'static> TahiniType for Vec<T> {
    fn to_tahini_enum(&self) -> TahiniEnum {
        TahiniEnum::Vec(self.iter().map(|e| e.to_tahini_enum()).collect::<Vec<_>>())
    }
    // fn tahini_policy_check(
    //     &self,
    //     members_fmt: &String,
    //     context: &UnprotectedContext,
    //     reason: &Reason,
    // ) -> bool {
    //     self.iter()
    //         .all(|x| x.tahini_policy_check(members_fmt, context, reason))
    // }
}

macro_rules! impl_tahini_trait_prim {
    ($ty: ty) => {
        impl TahiniType for $ty {
            fn to_tahini_enum(&self) -> TahiniEnum {
                TahiniEnum::Value(Box::new(self.clone()))
            }
            // fn tahini_policy_check(
            //     &self,
            //     _members_fmt: &String,
            //     _context: &UnprotectedContext,
            //     _reason: &Reason,
            // ) -> bool {
            //     true
            // }
        }
    };
}

impl_tahini_trait_prim!(u8);
impl_tahini_trait_prim!(u16);
impl_tahini_trait_prim!(u32);
impl_tahini_trait_prim!(i8);
impl_tahini_trait_prim!(i16);
impl_tahini_trait_prim!(i32);
impl_tahini_trait_prim!(usize);
impl_tahini_trait_prim!(String);
impl_tahini_trait_prim!(bool);

macro_rules! alohomora_type_tuple_impl {
  ($([$A:tt,$i:tt]),*) => (
    #[doc = "Library implementation of AlohomoraType. Do not copy this docstring!"]
    impl<$($A: TahiniType,)*> TahiniType for ($($A,)*) {
        fn to_tahini_enum(&self) -> TahiniEnum {
            #[allow(non_snake_case)]
            let ($($A,)*) = ($(self.$i.to_tahini_enum(),)*);
            TahiniEnum::Vec(vec![$($A,)*])
        }
    }
  );
}

alohomora_type_tuple_impl!([A, 0]);
alohomora_type_tuple_impl!([A, 0], [B, 1]);
alohomora_type_tuple_impl!([A, 0], [B, 1], [C, 2]);
alohomora_type_tuple_impl!([A, 0], [B, 1], [C, 2], [D, 3]);
alohomora_type_tuple_impl!([A, 0], [B, 1], [C, 2], [D, 3], [E, 4]);
alohomora_type_tuple_impl!([A, 0], [B, 1], [C, 2], [D, 3], [E, 4], [F, 5]);
alohomora_type_tuple_impl!([A, 0], [B, 1], [C, 2], [D, 3], [E, 4], [F, 5], [G, 6]);
alohomora_type_tuple_impl!(
    [A, 0],
    [B, 1],
    [C, 2],
    [D, 3],
    [E, 4],
    [F, 5],
    [G, 6],
    [H, 7]
);
alohomora_type_tuple_impl!(
    [A, 0],
    [B, 1],
    [C, 2],
    [D, 3],
    [E, 4],
    [F, 5],
    [G, 6],
    [H, 7],
    [I, 8]
);
alohomora_type_tuple_impl!(
    [A, 0],
    [B, 1],
    [C, 2],
    [D, 3],
    [E, 4],
    [F, 5],
    [G, 6],
    [H, 7],
    [I, 8],
    [J, 9]
);alohomora_type_tuple_impl!(
    [A, 0],
    [B, 1],
    [C, 2],
    [D, 3],
    [E, 4],
    [F, 5],
    [G, 6],
    [H, 7],
    [I, 8],
    [J, 9],
    [K, 10]
);
alohomora_type_tuple_impl!(
    [A, 0],
    [B, 1],
    [C, 2],
    [D, 3],
    [E, 4],
    [F, 5],
    [G, 6],
    [H, 7],
    [I, 8],
    [J, 9],
    [K, 10],
    [L, 11]
);
