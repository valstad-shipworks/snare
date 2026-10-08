//! A list that keeps its first entries in place and spills only the rest to the heap, for state a
//! hook reached from inside a C allocator changes: within its room, adding and removing entries
//! never allocate.

pub(crate) struct RoomVec<T, const N: usize> {
    room: [Option<T>; N],
    len: usize,
    spill: Vec<T>,
}

impl<T, const N: usize> RoomVec<T, N> {
    pub(crate) const fn new() -> Self {
        Self {
            room: [const { None }; N],
            len: 0,
            spill: Vec::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len + self.spill.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.room[..self.len].iter().flatten().chain(&self.spill)
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.room[..self.len]
            .iter_mut()
            .flatten()
            .chain(&mut self.spill)
    }

    pub(crate) fn find_mut(&mut self, matches: impl FnMut(&&mut T) -> bool) -> Option<&mut T> {
        self.iter_mut().find(matches)
    }

    pub(crate) fn push(&mut self, value: T) {
        if self.len < N {
            self.room[self.len] = Some(value);
            self.len += 1;
        } else {
            self.spill.push(value);
        }
    }

    /// Keeps only the entries `keep` accepts, in no particular order.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut i = 0;
        while i < self.len {
            if self.room[i].as_ref().is_some_and(&mut keep) {
                i += 1;
            } else {
                self.len -= 1;
                self.room.swap(i, self.len);
                self.room[self.len] = None;
            }
        }
        self.spill.retain(&mut keep);
        while self.len < N
            && let Some(value) = self.spill.pop()
        {
            self.room[self.len] = Some(value);
            self.len += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RoomVec;

    #[test]
    fn keeps_what_retain_keeps_across_room_and_spill() {
        let mut list = RoomVec::<u32, 4>::new();
        for n in 0..10 {
            list.push(n);
        }
        assert_eq!(list.len(), 10);
        list.retain(|&n| n % 3 != 0);
        let mut kept: Vec<_> = list.iter().copied().collect();
        kept.sort_unstable();
        assert_eq!(kept, [1, 2, 4, 5, 7, 8]);
        for n in list.iter_mut() {
            *n *= 10;
        }
        list.retain(|&n| n > 40);
        let mut kept: Vec<_> = list.iter().copied().collect();
        kept.sort_unstable();
        assert_eq!(kept, [50, 70, 80]);
        assert_eq!(list.len(), 3);
    }
}
