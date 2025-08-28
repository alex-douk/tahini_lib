// TODO(babman): move AnySerialize, AnyPolicySerializeDyn here, and use Sesame's macros to
//               automatically do their impl.
use alohomora::policy::AnyPolicy;
pub use alohomora::policy::AnyPolicySerializeDyn as TahiniPolicyDyn;
pub use alohomora::sesame_type_dyns::AnySerialize as TahiniDataDyn;

pub type TahiniDataType = Box<dyn TahiniDataDyn>;
pub type TahiniPolicy = AnyPolicy<dyn TahiniPolicyDyn>;
