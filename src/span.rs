use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }
    pub fn shift(&mut self, offset: usize) {
        self.start += offset;
        self.end += offset;
    }
    pub fn shift_isize(&mut self, offset: isize) {
        self.start = (self.start as isize + offset) as usize;
        self.end = (self.end as isize + offset) as usize;
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}
