#![feature(rustc_private)]
extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_query_system;
extern crate rustc_span;
extern crate rustc_stable_hash;

pub mod utils;
use std::collections::{HashMap, HashSet};
use std::fmt::format;
use std::fs::File;
use std::hash::Hash;
use std::io::{self, BufRead, Write};

use log::{error, trace, warn};
use rustc_data_structures::fingerprint::Fingerprint;
use rustc_data_structures::stable_hasher::{HashStable, StableHasher};
use rustc_hir::def_id::{CrateNum, DefId, LOCAL_CRATE};
use rustc_hir::hir_id::HirId;
use rustc_middle::ty::TyCtxt;
use rustc_plugin::{CrateFilter, RustcPlugin, Utf8Path};
use rustc_query_system::ich::StableHashingContext;
use utils::dependency::Crate;

pub struct AttestPlugin;

pub struct HashAndDumpCallback;

fn find_sesame_crate(tcx: TyCtxt<'_>) -> Option<CrateNum> {
    tcx.crates(())
        .iter()
        .find(|&&cnum| tcx.crate_name(cnum).as_str() == "alohomora")
        .copied()
}

fn find_policy_trait_def_id(tcx: TyCtxt<'_>, sesame_crate_num: CrateNum) -> DefId {
    let traits = tcx.traits(sesame_crate_num);
    let pol_trait = traits
        .iter()
        .find(|&tr| tcx.def_path_str(tr) == "alohomora::policy::Policy");
    pol_trait
        .copied()
        .expect("Couldn't find policy trait in Sesame")
}

//The next steps are:
//Check if current crate implements policies.
//If they do, create a JSON file that will contain all type names with a hash associated to it.
//Probably the best way to do so would be to hold a HashMap and then serialize it all as a JSON.
fn hash_impls_of_trait(tcx: TyCtxt<'_>, trait_id: DefId) -> Option<HashMap<String, String>> {
    let local_pol_impls = tcx.all_local_trait_impls(()).get(&trait_id);

    //If the current crate has Sesame as a dependency but does not implement policies, for now we
    //silently drop. We might check for implementations of Critical Regions down the road.
    if local_pol_impls.is_none() {
        return None;
    }

    let local_pol_impls =
        local_pol_impls.expect("Local crate should implement at least one policy");

    let mut context = StableHashingContext::new(tcx.sess, tcx.untracked());

    //Goes from a LocalDefId all the way to a slice of HIR impl items.
    let local_pol_impls = local_pol_impls
        .iter()
        .map(|local_def_id| (local_def_id.to_def_id(), HirId::make_owner(*local_def_id)))
        .map(|hir_id| (hir_id.0, tcx.hir_node(hir_id.1)))
        .map(|node| (node.0, node.1.expect_item()))
        .map(|hir_item| (hir_item.0, hir_item.1.expect_impl().items))
        .collect::<Vec<_>>();

    //For each `impl Policy` block, hash all methods.
    //We can iterate over the optimized MIR for methods.
    //For associated types, we can just hash the type declaration.
    //This will be useful when handling TahiniTransform<From/Into>.
    //We currently generate a hash per block.
    let mut hashed_data = Vec::new();
    for impel in local_pol_impls.iter() {
        let mut hasher = StableHasher::new();
        let (ty, items) = impel;
        for item in items.iter() {
            let id = item.id.owner_id.to_def_id();
            let body = tcx.optimized_mir(id);
            body.hash_stable(&mut context, &mut hasher);
        }
        let impl_fingerprint: Fingerprint = hasher.finish();
        hashed_data.push((tcx.def_path_str(ty), impl_fingerprint.to_hex()));
    }

    Some(HashMap::from_iter(hashed_data.into_iter()))
    //TODO(put everything in hashmap, dump in correct standalone file)
    //Next step is to aggregate hashes of dependencies + local definitions for a given target.
    //We will have to be careful to not double include stuff. Therefore might need to only target
    //used crates and not all crates.
}

fn find_dump_file(tcx: TyCtxt<'_>) -> Result<File, std::io::Error> {
    let crate_symbol = tcx.crate_name(LOCAL_CRATE);
    let file_path = format!(
        "./policy_hashes/{}_policy_hashes.json",
        crate_symbol.as_str()
    );
    File::create(file_path)
}

fn dump_local_to_file(hashes: HashMap<String, String>, file: File) -> Result<(), std::io::Error> {
    serde_json::to_writer_pretty(file, &hashes)?;
    Ok(())
}

fn add_to_hash_index(crate_name: String) -> Result<(), std::io::Error> {
    let mut index_file = File::options()
        .create(true)
        .append(true)
        .open("./policy_hashes/hash_index")?;
    write!(index_file, "{}", crate_name)
}

fn find_all_hashed_dependencies(tcx: TyCtxt<'_>) -> Vec<String> {
    let used_crate_names: HashSet<_> = tcx
        .used_crates(())
        .into_iter()
        .map(|krate| tcx.crate_name(*krate).to_string())
        .collect();
    let already_hashed = File::open("./policy_hashes/hash_index");
    if already_hashed.is_err() {
        return Vec::new();
    }
    let already_hashed: HashSet<_> = std::io::BufReader::new(already_hashed.unwrap())
        .lines()
        .map_while(Result::ok)
        .collect();

    let intersect: Vec<_> = already_hashed.intersection(&used_crate_names).collect();
    Vec::new()
}

///For a given set of dependencies,
// fn read_all_dependency_hashes(deps: Vec<&String>) -> HashMap<String, HashMap<String, String>> {
//
// }
//
fn attest_crate(mut kr: Crate) -> Result<(), io::Error> {
    trace!("Starting to attest crate : {:?}", kr.name());
    kr.prune_deps()?;
    kr.get_leaves()?;
    kr.dump_local_to_file()?;
    Ok(())
}

impl rustc_driver::Callbacks for HashAndDumpCallback {
    fn after_expansion<'tcx>(
        &mut self,
        _compiler: &rustc_interface::interface::Compiler,
        _tcx: rustc_middle::ty::TyCtxt<'tcx>,
    ) -> rustc_driver::Compilation {
        rustc_driver::Compilation::Continue
    }

    fn after_analysis<'tcx>(
        &mut self,
        _compiler: &rustc_interface::interface::Compiler,
        tcx: rustc_middle::ty::TyCtxt<'tcx>,
    ) -> rustc_driver::Compilation {
        let krate = Crate::from_compiler(tcx);
        match krate {
            None => rustc_driver::Compilation::Continue,
            Some(mut kr) => {
                kr.fetch_dependencies(tcx);
                let name = kr.name().clone();
                match attest_crate(kr) {
                    Ok(_) => rustc_driver::Compilation::Continue,
                    Err(e) => {
                        error!(
                            "For crate : {}, During attestation, got error : {:?}",
                            name, e
                        );
                        rustc_driver::Compilation::Stop
                    }
                }
            }
        }
    }
}

impl RustcPlugin for AttestPlugin {
    type Args = ();

    fn version(&self) -> std::borrow::Cow<'static, str> {
        env!("CARGO_PKG_VERSION").into()
    }

    fn driver_name(&self) -> std::borrow::Cow<'static, str> {
        "attest_driver".into()
    }

    fn args(&self, _target_dir: &Utf8Path) -> rustc_plugin::RustcPluginArgs<Self::Args> {
        let filter = CrateFilter::AllCrates;
        rustc_plugin::RustcPluginArgs { args: (), filter }
    }
    fn run(
        self,
        compiler_args: Vec<String>,
        _plugin_args: Self::Args,
    ) -> rustc_interface::interface::Result<()> {
        let mut callback = HashAndDumpCallback;
        warn!("Logging started");
        rustc_driver::RunCompiler::new(&compiler_args, &mut callback).run();
        Ok(())
    }
}
