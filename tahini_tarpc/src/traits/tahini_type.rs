use alohomora::bbox::BBox;
use alohomora::{SesameType, SesameTypeEnum};

use crate::enums::TahiniEnum;
use crate::traits::{TahiniDataDyn, TahiniPolicyDyn};

// TahiniType
pub trait TahiniType: Send {
    fn to_tahini_enum(self) -> TahiniEnum;
}

// TODO(babman): these impls go away when generic coercion is stable in Sesame.

// TahiniType for BBox.
impl<T: TahiniDataDyn, P: TahiniPolicyDyn> TahiniType for BBox<T, P> {
    fn to_tahini_enum(self) -> TahiniEnum {
        if let SesameTypeEnum::BBox(bbox) = self.to_enum() {
            TahiniEnum::BBox(bbox)
        } else {
            unreachable!()
        }
    }
}

// TahiniType for Option.
impl<T: TahiniType> TahiniType for Option<T> {
    fn to_tahini_enum(self) -> TahiniEnum {
        TahiniEnum::Option(self.map(T::to_tahini_enum).map(Box::new))
    }
}

// TahiniType for Result.
impl<T: TahiniType, E: TahiniType> TahiniType for Result<T, E> {
    fn to_tahini_enum(self) -> TahiniEnum {
        TahiniEnum::Result(
            self.map(T::to_tahini_enum)
                .map(Box::new)
                .map_err(E::to_tahini_enum)
                .map_err(Box::new),
        )
    }
}

// TahiniType for Vec.
impl<T: TahiniType> TahiniType for Vec<T> {
    fn to_tahini_enum(self) -> TahiniEnum {
        TahiniEnum::Vec(self.into_iter().map(T::to_tahini_enum).collect::<Vec<_>>())
    }
}

macro_rules! impl_tahini_trait_prim {
    ($ty: ty) => {
        impl TahiniType for $ty {
            fn to_tahini_enum(self) -> TahiniEnum {
                TahiniEnum::Value(Box::new(self))
            }
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
        fn to_tahini_enum(self) -> TahiniEnum {
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
