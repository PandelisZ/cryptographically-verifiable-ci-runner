//! `vci ci --partition I/N`: N CI jobs share what a plan leaves to run.
//!
//! Every unit the plan runs belongs to exactly one partition, chosen from
//! the checkout alone. A project whose units are all files is split by
//! size (2.4.0, [`Split::balanced`]); any other unit by its test id: the
//! first 8 bytes of its storage key (BLAKE3 of the test id,
//! [`vci_core::test_key`]), big-endian, modulo N. So the split is the same
//! on every machine and in every job, whatever the order of the plan,
//! what it skips, or what the other partitions do. Units the plan skips are skipped
//! in every partition. A project that runs everything and could not be
//! listed (no units to split) runs whole in every partition that cannot
//! list it: each job decides from its own listing and cannot know whether
//! another one listed it, so an unlisted project may run in more than one
//! job, never in none (fail open).

use std::fmt;
use std::str::FromStr;

use crate::plan::PlanResult;

/// `I/N`: this job is partition `index` (1-based) of `count`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub index: u32,
    pub count: u32,
}

impl FromStr for Partition {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (i, n) = s
            .split_once('/')
            .ok_or_else(|| format!("{s:?} is not I/N (e.g. 2/3)"))?;
        let num = |what: &str, v: &str| {
            v.trim()
                .parse::<u32>()
                .map_err(|_| format!("{what} in {s:?} is not a whole number"))
        };
        let (index, count) = (num("I", i)?, num("N", n)?);
        if count == 0 {
            return Err(format!("N in {s:?} must be at least 1"));
        }
        if index == 0 || index > count {
            return Err(format!(
                "I in {s:?} must be between 1 and {count} (partitions are numbered from 1)"
            ));
        }
        Ok(Partition { index, count })
    }
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.index, self.count)
    }
}

/// The partition (0-based) of `count` a test id belongs to.
pub fn bucket(test_id: &str, count: u32) -> u32 {
    let key = vci_core::test_key(test_id);
    let head = key
        .get(..16)
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    (head % u64::from(count.max(1))) as u32
}

impl Partition {
    /// Whether this partition runs the unit `test_id`.
    pub fn owns(&self, test_id: &str) -> bool {
        bucket(test_id, self.count) == self.index - 1
    }
}

/// What one project of the plan runs in this partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Share {
    /// These units (indexes into [`PlanResult::files`]) of the `of` units
    /// the project runs over all partitions.
    Units { mine: Vec<usize>, of: usize },
    /// The project runs everything and its units could not be listed: it
    /// runs whole here (in every partition that could not list it).
    Whole,
}

/// A plan split for one partition: what each project runs in it.
#[derive(Debug, Clone)]
pub struct Split {
    pub part: Partition,
    /// Per project, in the order of [`PlanResult::projects`].
    pub shares: Vec<Share>,
}

impl Split {
    /// `root`: the repository root, where each project's files are weighed
    /// (see [`Split::from_weighed`]).
    pub fn new(res: &PlanResult, part: Partition, root: &std::path::Path) -> Self {
        let run_all: Vec<bool> = res
            .projects
            .iter()
            .map(|p| res.run_all.is_some() || p.run_all.is_some())
            .collect();
        let files: Vec<(usize, &str, bool)> = res
            .files
            .iter()
            .map(|f| (f.project_idx, f.test_id.as_str(), f.skip))
            .collect();
        let by_hash = std::env::var("VCI_PARTITION_BY").is_ok_and(|v| v == "hash");
        let weights: Vec<Option<u64>> = res
            .files
            .iter()
            .map(|f| {
                if by_hash {
                    return None;
                }
                let dir = res
                    .projects
                    .get(f.project_idx)
                    .map(|p| root.join(&p.path))
                    .unwrap_or_else(|| root.to_path_buf());
                std::fs::metadata(dir.join(&f.file))
                    .ok()
                    .filter(std::fs::Metadata::is_file)
                    .map(|m| m.len())
            })
            .collect();
        Self::from_weighed(part, &run_all, &files, &weights)
    }

    /// `run_all`: per project, whether it runs everything; `files`: the
    /// plan's units as (project, test id, skip).
    #[cfg(test)]
    fn from_parts(part: Partition, run_all: &[bool], files: &[(usize, &str, bool)]) -> Self {
        Self::from_weighed(part, run_all, files, &vec![None; files.len()])
    }

    /// The partition of each listed unit of a project whose units are all
    /// files (`weights[k]`: the file's size), by test id (2.4.0): every
    /// listed unit, skipped or not, largest first, goes to the partition
    /// with the least weight so far (ties: the lowest), so the split is
    /// the same in every job that lists the same checkout, whatever each
    /// job's plan skips (a job run again after the others pushed their
    /// attestations agrees with them). A file's size stands for how long
    /// its tests take: on vex's Rails tests the hash split gave the two
    /// jobs 2,762 and 3,231 seconds of tests, this one 3,047 and 2,946.
    /// `None` for a project with a unit that is not a file (a cargo unit):
    /// its units are split by [`bucket`].
    fn balanced(
        count: u32,
        pi: usize,
        files: &[(usize, &str, bool)],
        weights: &[Option<u64>],
    ) -> Option<std::collections::BTreeMap<String, u32>> {
        let mut mine: Vec<(u64, &str)> = Vec::new();
        for (k, (p, id, _)) in files.iter().enumerate() {
            if *p == pi {
                mine.push((weights.get(k).copied().flatten()?, id));
            }
        }
        mine.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        let mut load = vec![0u64; count.max(1) as usize];
        let mut out = std::collections::BTreeMap::new();
        for (w, id) in mine {
            let (i, _) = load
                .iter()
                .enumerate()
                .min_by_key(|(i, l)| (**l, *i))
                .expect("at least one partition");
            load[i] += w.max(1);
            out.insert(id.to_owned(), i as u32);
        }
        Some(out)
    }

    fn from_weighed(
        part: Partition,
        run_all: &[bool],
        files: &[(usize, &str, bool)],
        weights: &[Option<u64>],
    ) -> Self {
        let shares = run_all
            .iter()
            .enumerate()
            .map(|(pi, &all)| {
                // A project that runs everything runs every listed unit,
                // whatever its verdict says.
                let to_run: Vec<usize> = files
                    .iter()
                    .enumerate()
                    .filter(|(_, (p, _, skip))| *p == pi && (all || !skip))
                    .map(|(k, _)| k)
                    .collect();
                // Another job may have listed it and run only its own
                // share: running it whole here is the only way its units
                // run in at least one job.
                if all && to_run.is_empty() {
                    return Share::Whole;
                }
                let of = to_run.len();
                let owners = Self::balanced(part.count, pi, files, weights);
                let mine = to_run
                    .into_iter()
                    .filter(|&k| match owners.as_ref().and_then(|o| o.get(files[k].1)) {
                        Some(&i) => i == part.index - 1,
                        None => part.owns(files[k].1),
                    })
                    .collect();
                Share::Units { mine, of }
            })
            .collect();
        Split { part, shares }
    }

    /// Units this partition runs.
    pub fn units(&self) -> usize {
        self.shares
            .iter()
            .map(|s| match s {
                Share::Units { mine, .. } => mine.len(),
                _ => 0,
            })
            .sum()
    }

    /// Units all partitions run (of the projects whose units are listed).
    pub fn total(&self) -> usize {
        self.shares
            .iter()
            .map(|s| match s {
                Share::Units { of, .. } => *of,
                _ => 0,
            })
            .sum()
    }

    /// Whether this partition runs `files[k]` of the plan.
    pub fn runs(&self, k: usize) -> bool {
        self.shares
            .iter()
            .any(|s| matches!(s, Share::Units { mine, .. } if mine.contains(&k)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_i_of_n() {
        assert_eq!(
            "2/3".parse::<Partition>(),
            Ok(Partition { index: 2, count: 3 })
        );
        assert_eq!(
            "1/1".parse::<Partition>(),
            Ok(Partition { index: 1, count: 1 })
        );
        assert_eq!("3/3".parse::<Partition>().unwrap().to_string(), "3/3");
        for bad in [
            "0/3", "4/3", "3/0", "0/0", "1", "a/3", "1/b", "-1/3", "", "1/3/4",
        ] {
            assert!(bad.parse::<Partition>().is_err(), "{bad}");
        }
    }

    /// Every id is in exactly one partition, the same one every time, and
    /// with enough ids every partition gets some.
    #[test]
    fn every_unit_in_exactly_one_partition() {
        let ids: Vec<String> = (0..300).map(|i| format!("src/t{i}.test.ts")).collect();
        for n in 1..=7u32 {
            let parts: Vec<Partition> =
                (1..=n).map(|index| Partition { index, count: n }).collect();
            let mut sizes = vec![0usize; n as usize];
            for id in &ids {
                let owners: Vec<&Partition> = parts.iter().filter(|p| p.owns(id)).collect();
                assert_eq!(owners.len(), 1, "{id} in {n} partitions: {owners:?}");
                sizes[owners[0].index as usize - 1] += 1;
                assert_eq!(bucket(id, n), bucket(id, n));
            }
            assert!(sizes.iter().all(|&s| s > 0), "{n}: {sizes:?}");
        }
        // The documented function of the storage key, so every job (and
        // anything reproducing the split) agrees.
        let key = vci_core::test_key("a#lib");
        let head = u64::from_str_radix(&key[..16], 16).unwrap();
        assert_eq!(bucket("a#lib", 5), (head % 5) as u32);
    }

    #[test]
    fn split_of_a_plan() {
        // Project 0: listed, two units skipped; project 1: runs everything,
        // listed (its skip flags do not matter); project 2: runs
        // everything, not listed.
        let ids: Vec<String> = (0..40).map(|i| format!("p/t{i}")).collect();
        let mut files: Vec<(usize, &str, bool)> = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            files.push((if i < 20 { 0 } else { 1 }, id.as_str(), i % 10 == 0));
        }
        let run_all = [false, true, true];
        let n = 3;
        let mut seen = vec![0usize; files.len()];
        for index in 1..=n {
            let s = Split::from_parts(Partition { index, count: n }, &run_all, &files);
            assert_eq!(s.total(), 18 + 20);
            // Unlisted: whole in every partition (none can know another
            // listed it).
            assert_eq!(s.shares[2], Share::Whole, "{index}");
            for (pi, share) in s.shares.iter().take(2).enumerate() {
                let Share::Units { mine, of } = share else {
                    panic!("{share:?}")
                };
                assert_eq!(*of, if pi == 0 { 18 } else { 20 });
                for &k in mine {
                    assert_eq!(files[k].0, pi);
                    assert!(s.runs(k));
                    seen[k] += 1;
                }
            }
        }
        for (k, (p, _, skip)) in files.iter().enumerate() {
            let want = usize::from(*p == 1 || !skip);
            assert_eq!(seen[k], want, "{:?}", files[k]);
        }
        // One partition: everything the plan runs.
        let s = Split::from_parts(Partition { index: 1, count: 1 }, &run_all, &files);
        assert_eq!(s.units(), s.total());
    }

    /// Projects whose units are all files are split by size: each listed
    /// unit in exactly one partition, the same whatever the plan skips, and
    /// the partitions' sizes close; a project with a unit that is not a
    /// file is split by test id as before.
    #[test]
    fn files_are_split_by_size_whatever_the_plan_skips() {
        let ids: Vec<String> = (0..60).map(|i| format!("test/t{i}_test.rb")).collect();
        let weights: Vec<Option<u64>> = (0..60).map(|i| Some(100 + (i * 37 % 1000))).collect();
        let n = 3;
        let total: u64 = weights.iter().map(|w| w.unwrap()).sum();
        for skips in [0usize, 2, 7] {
            let files: Vec<(usize, &str, bool)> = ids
                .iter()
                .enumerate()
                .map(|(i, id)| (0, id.as_str(), skips > 0 && i % skips == 0))
                .collect();
            let mut owner = vec![0usize; ids.len()];
            let mut size = vec![0u64; n as usize];
            for index in 1..=n {
                let s =
                    Split::from_weighed(Partition { index, count: n }, &[false], &files, &weights);
                let Share::Units { mine, .. } = &s.shares[0] else {
                    panic!()
                };
                for &k in mine {
                    owner[k] = index as usize;
                    size[index as usize - 1] += weights[k].unwrap();
                }
            }
            for (k, f) in files.iter().enumerate() {
                assert_eq!(owner[k] != 0, !f.2, "{f:?}");
            }
            if skips == 0 {
                let (lo, hi) = (*size.iter().min().unwrap(), *size.iter().max().unwrap());
                assert!(hi - lo <= 1100, "{size:?} of {total}");
            }
            // The same owner as with nothing skipped.
            let all: Vec<(usize, &str, bool)> =
                ids.iter().map(|id| (0, id.as_str(), false)).collect();
            for index in 1..=n {
                let s =
                    Split::from_weighed(Partition { index, count: n }, &[false], &all, &weights);
                let Share::Units { mine, .. } = &s.shares[0] else {
                    panic!()
                };
                for &k in mine {
                    assert!(owner[k] == 0 || owner[k] == index as usize, "{}", ids[k]);
                }
            }
        }
        // One unit without a size: the project is split by test id.
        let mut w2 = weights.clone();
        w2[5] = None;
        let files: Vec<(usize, &str, bool)> =
            ids.iter().map(|id| (0, id.as_str(), false)).collect();
        let s = Split::from_weighed(Partition { index: 2, count: n }, &[false], &files, &w2);
        let Share::Units { mine, .. } = &s.shares[0] else {
            panic!()
        };
        for &k in mine {
            assert_eq!(bucket(&ids[k], n), 1);
        }
    }

    /// Each job lists on its own: a job that listed a project runs its
    /// share, and every job that could not list it runs it whole, whichever
    /// partition it is, so no unit is left to a job that skipped it.
    #[test]
    fn a_job_that_cannot_list_runs_the_project_whole() {
        let ids: Vec<String> = (0..30).map(|i| format!("rs/t{i}#lib")).collect();
        let listed: Vec<(usize, &str, bool)> =
            ids.iter().map(|id| (0, id.as_str(), false)).collect();
        let n = 3;
        for lists in 1..=n {
            // Only partition `lists` could list the project.
            let mut runs = vec![0usize; ids.len()];
            let mut whole = 0;
            for index in 1..=n {
                let part = Partition { index, count: n };
                let files: &[(usize, &str, bool)] = if index == lists { &listed } else { &[] };
                let s = Split::from_parts(part, &[true], files);
                match &s.shares[0] {
                    Share::Whole => {
                        assert_ne!(index, lists);
                        whole += 1;
                    }
                    Share::Units { mine, of } => {
                        assert_eq!((index, *of), (lists, ids.len()));
                        for &k in mine {
                            runs[k] += 1;
                        }
                    }
                }
            }
            assert_eq!(whole, n - 1, "listed by {lists}");
            // Every unit runs in some job: in its owner's share when the
            // owner listed it, else in a job that runs the project whole.
            for (k, id) in ids.iter().enumerate() {
                let owner = bucket(id, n) + 1;
                assert_eq!(runs[k], usize::from(owner == lists), "{id}");
                assert!(runs[k] == 1 || whole > 0, "{id} runs nowhere");
            }
        }
    }
}
