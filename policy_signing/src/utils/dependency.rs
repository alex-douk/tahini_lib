#![feature(rustc_private)]

extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_query_system;
extern crate rustc_span;
extern crate rustc_stable_hash;

use log::{error, trace};
use rustc_data_structures::fingerprint::Fingerprint;
use rustc_data_structures::stable_hasher::{HashStable, StableHasher};
use rustc_hir::def_id::{CrateNum, DefId, LOCAL_CRATE};
use rustc_hir::hir_id::HirId;
use rustc_middle::ty::TyCtxt;
use rustc_query_system::ich::StableHashingContext;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::fs::File;
use std::hash::{Hash, RandomState};
use std::io;
use std::io::{BufRead, Write};

static POLICY_DIRECTORY: &'static str = "./policy_hashes";
static HASH_INDEX: &'static str = "./policy_hashes/hash_index";

#[derive(serde::Serialize, serde::Deserialize)]
struct JsonDumpStruct {
    dependency_hashes: HashMap<String, String>,
    local_summary_hash: String,
    local_impls_hashes: HashMap<String, String>,
}

fn format_file_name(string: &String) -> String {
    format!("./policy_hashes/{}_policy_hashes.json", string)
}

fn find_sesame_crate(tcx: TyCtxt<'_>) -> Option<CrateNum> {
    tcx.used_crates(())
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
}

#[derive(Eq, Clone, PartialOrd, Ord)]
pub struct CrateName(pub String);

impl PartialEq for CrateName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Hash for CrateName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Display for CrateName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for CrateName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct Crate {
    my_crate_name: String,
    local_implementations_stable_hashes: HashMap<String, String>,
    dependencies_names: Vec<CrateName>,
    dependencies_hashes: Vec<String>,
}

impl Crate {
    pub fn from_compiler(tcx: TyCtxt<'_>) -> Option<Self> {
        match find_sesame_crate(tcx) {
            Some(sesame_crate_num) => {
                let pol_id = find_policy_trait_def_id(tcx, sesame_crate_num);
                Some(Self {
                        my_crate_name: tcx.crate_name(LOCAL_CRATE).to_ident_string(),
                        local_implementations_stable_hashes: hash_impls_of_trait(tcx, pol_id).unwrap_or_default(),
                        dependencies_names: Vec::new(),
                        dependencies_hashes: Vec::new(),
                })
            }
            None => None,
        }
    }

    pub fn name(&self) -> &String {
        &self.my_crate_name
    }

    pub fn fetch_dependencies(&mut self, tcx: TyCtxt<'_>) {
        self.dependencies_names = tcx
            .used_crates(())
            .iter()
            .map(|x| CrateName(tcx.crate_name(*x).to_ident_string()))
            .collect();
    }

    pub fn prune_deps(&mut self) -> Result<(), io::Error> {
        let already_hashed = File::options().read(true).open(HASH_INDEX);
        if already_hashed.is_err() {
            error!("Couldn't find hash index file at {:?}", HASH_INDEX);
            self.dependencies_names = Vec::new();
        }
        let already_hashed = already_hashed?;
        let already_hashed: Vec<_> = std::io::BufReader::new(already_hashed)
            .lines()
            .map_while(Result::ok)
            .map(|x| CrateName(x))
            .collect();
        let already_hashed: HashSet<_> = already_hashed.into_iter().collect();
        let my_deps_hashset: HashSet<_> = self.dependencies_names.clone().into_iter().collect();
        let mut my_deps_vec: Vec<_> = my_deps_hashset
            .intersection(&already_hashed)
            .cloned()
            .collect();
        my_deps_vec.sort();
        self.dependencies_names = my_deps_vec;
        // trace!("For crate : {:?}, pruned dependencies are : {:#?}", self.my_crate_name, &self.dependencies_names);
        Ok(())
    }

    pub fn get_leaves(&mut self) -> Result<(), io::Error> {
        let mut dep_hashes = Vec::with_capacity(self.dependencies_names.len());
        for dep in self.dependencies_names.iter() {
            let dep_file = File::options().read(true).open(format_file_name(&dep.0))?;
            let first_line = std::io::BufReader::new(dep_file).lines().next();
            match first_line {
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Hash file for dependency {:?} does not contain data", dep),
                    ));
                }
                Some(hash_line) => {
                    let dep_hash = hash_line?;
                    dep_hashes.push((dep, dep_hash));
                }
            }
        }
        dep_hashes.sort_by_key(|x| x.0);
        self.dependencies_hashes = dep_hashes.into_iter().map(|x| x.1).collect();
        // trace!("For crate : {:?}, dependencies hashes are : {:#?}", self.my_crate_name, &self.dependencies_hashes);
        Ok(())
    }

    pub fn dump_local_to_file(self) -> Result<(), io::Error> {
        let file_path = format_file_name(&self.my_crate_name);
        let mut file = File::create(file_path)?;
        self.register_to_index()?;
        let deps_hashes_map: HashMap<String, String, RandomState> = HashMap::from_iter(
            self.dependencies_names
                .into_iter()
                .map(|x| x.0)
                .zip(self.dependencies_hashes),
        );
        let dep_hashes_bytes = serde_json::to_vec(&deps_hashes_map)?;
        let jsoned = serde_json::to_vec(&self.local_implementations_stable_hashes)?;
        let dep_tree_hash = sha256::digest(dep_hashes_bytes);
        let local_hash = sha256::digest(jsoned);
        let mut total_hash = dep_tree_hash.clone();
        total_hash.push_str(&local_hash);
        let total_hash = sha256::digest(total_hash.as_bytes());

        let expanded = JsonDumpStruct {
            dependency_hashes: deps_hashes_map,
            local_summary_hash: local_hash,
            local_impls_hashes: self.local_implementations_stable_hashes,
        };

        write!(file, "{}\n", total_hash)?;
        serde_json::to_writer_pretty(file, &expanded)?;
        Ok(())
    }

    fn register_to_index(&self) -> Result<(), io::Error> {
        let mut index_file = File::options().create(true).append(true).open(HASH_INDEX)?;
        write!(index_file, "{}\n", self.my_crate_name)
    }

    pub fn get_pruned(&self) -> &Vec<CrateName> {
        &self.dependencies_names
    }
}

